#pragma warning disable BL0006, ASP0006
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Infrastructure;
using Microsoft.AspNetCore.Components.RenderTree;
using Microsoft.AspNetCore.Components.Routing;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.JSInterop;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Integration.Tests;

/// <summary>A node in the rendered tree (elements only; text is aggregated).</summary>
public sealed class PageANode
{
    public string Tag { get; init; } = "";
    public Dictionary<string, object?> Attrs { get; } = [];
    public Dictionary<string, ulong> Events { get; } = [];
    public List<PageANode> Children { get; } = [];
    public StringBuilder OwnText { get; } = new();

    public string Text
    {
        get
        {
            var sb = new StringBuilder(OwnText.ToString());
            foreach (var c in Children) sb.Append(' ').Append(c.Text);
            return System.Text.RegularExpressions.Regex.Replace(sb.ToString(), @"\s+", " ").Trim();
        }
    }

    public IEnumerable<PageANode> Descendants()
    {
        foreach (var c in Children)
        {
            yield return c;
            foreach (var d in c.Descendants()) yield return d;
        }
    }

    public string? Attr(string name) => Attrs.TryGetValue(name, out var v) ? v?.ToString() : null;
}

/// <summary>
/// A minimal headless Blazor renderer: renders a real page component against the real app services
/// and dispatches real events (click / input / change) through the renderer, so a page's handlers and
/// its post-click branches execute without a browser or circuit.
/// </summary>
public sealed class PageARenderer : Renderer
{
    private readonly List<Exception> _errors = [];
    private int _rootId;

    public PageARenderer(IServiceProvider sp) : base(sp, sp.GetRequiredService<ILoggerFactory>()) { }

    public override Dispatcher Dispatcher { get; } = Dispatcher.CreateDefault();

    protected override Task UpdateDisplayAsync(in RenderBatch renderBatch) => Task.CompletedTask;

    // Pages declare @rendermode InteractiveServer; here we render them in-process regardless.
    protected override IComponent ResolveComponentForRenderMode(
        Type componentType, int? parentComponentId, IComponentActivator componentActivator, IComponentRenderMode renderMode)
        => componentActivator.CreateInstance(componentType);

    /// <summary>Where the page last asked to navigate (static SSR NavigateTo surfaces as NavigationException).</summary>
    public string? LastNavigation { get; private set; }

    protected override void HandleException(Exception exception)
    {
        if (exception is NavigationException ne) LastNavigation = ne.Location;
        else _errors.Add(exception);
    }

    public IReadOnlyList<Exception> Errors => _errors;

    public async Task StartAsync(Type page, IDictionary<string, object?>? parameters = null)
    {
        _rootId = await Dispatcher.InvokeAsync(async () =>
        {
            var c = InstantiateComponent(page);
            var id = AssignRootComponentId(c);
            _rootId = id;
            await RenderRootComponentAsync(id, ParameterView.FromDictionary(parameters ?? new Dictionary<string, object?>()));
            return id;
        });
        ThrowIfErrors();
    }

    public void ThrowIfErrors()
    {
        if (_errors.Count > 0) throw new AggregateException(_errors.ToArray());
    }

    public PageANode Tree()
    {
        var root = new PageANode { Tag = "#root" };
        Build(_rootId, root);
        return root;
    }

    public string Text => Tree().Text;

    private void Build(int componentId, PageANode parent)
    {
        var frames = GetCurrentRenderTreeFrames(componentId);
        BuildRange(frames.Array, 0, frames.Count, parent);
    }

    private void BuildRange(RenderTreeFrame[] f, int start, int end, PageANode parent)
    {
        var i = start;
        while (i < end)
        {
            ref var fr = ref f[i];
            switch (fr.FrameType)
            {
                case RenderTreeFrameType.Element:
                {
                    var n = new PageANode { Tag = fr.ElementName };
                    var stop = i + fr.ElementSubtreeLength;
                    var j = i + 1;
                    while (j < stop && f[j].FrameType == RenderTreeFrameType.Attribute)
                    {
                        if (f[j].AttributeEventHandlerId != 0) n.Events[f[j].AttributeName] = f[j].AttributeEventHandlerId;
                        else n.Attrs[f[j].AttributeName] = f[j].AttributeValue;
                        j++;
                    }
                    BuildRange(f, j, stop, n);
                    parent.Children.Add(n);
                    i = stop;
                    break;
                }
                case RenderTreeFrameType.Text:
                    parent.OwnText.Append(fr.TextContent);
                    i++;
                    break;
                case RenderTreeFrameType.Markup:
                    parent.OwnText.Append(' ').Append(System.Net.WebUtility.HtmlDecode(System.Text.RegularExpressions.Regex.Replace(fr.MarkupContent, "<[^>]+>", " "))).Append(' ');
                    i++;
                    break;
                case RenderTreeFrameType.Component:
                {
                    var stop = i + fr.ComponentSubtreeLength;
                    Build(fr.ComponentId, parent);
                    i = stop;
                    break;
                }
                default:
                    i++;
                    break;
            }
        }
    }

    private async Task DispatchAsync(ulong id, EventArgs args)
    {
        await Dispatcher.InvokeAsync(() => DispatchEventAsync(id, null, args));
        ThrowIfErrors();
    }

    private static string Norm(string s) => System.Text.RegularExpressions.Regex.Replace(s, @"\s+", " ").Trim();

    /// <summary>Finds the tightest element carrying <paramref name="evt"/> whose text contains <paramref name="text"/>.</summary>
    public PageANode FindEvent(string evt, string text, int nth = 0, string? tag = null)
    {
        var root = Tree();
        var hits = root.Descendants()
            .Where(n => n.Events.ContainsKey(evt) && (tag is null || n.Tag == tag) && n.Text.Contains(text, StringComparison.OrdinalIgnoreCase))
            .OrderBy(n => n.Text == text ? 0 : 1).ThenBy(n => n.Text.Length)
            .ToList();
        if (hits.Count <= nth)
            throw new InvalidOperationException($"No '{evt}' element containing '{text}' (nth={nth}). Page text: {Truncate(root.Text)}");
        return hits[nth];
    }

    /// <summary>Assert the page text contains the text; the failure shows the page.</summary>
    public void Expect(string text)
    {
        if (!Has(text)) throw new Xunit.Sdk.XunitException($"Expected page to contain '{text}'. Page text: {Truncate(Text)}");
    }

    public bool Has(string text) => Text.Contains(text, StringComparison.Ordinal);

    public async Task ClickAsync(string text, int nth = 0)
    {
        var n = FindEvent("onclick", text, nth);
        await DispatchAsync(n.Events["onclick"], new MouseEventArgs());
    }

    /// <summary>Click the nth enabled button/anchor-with-handler by exact label.</summary>
    public async Task ClickButtonAsync(string label, int nth = 0)
    {
        var n = FindEvent("onclick", label, nth, tag: "button");
        await DispatchAsync(n.Events["onclick"], new MouseEventArgs());
    }

    public bool HasButton(string label) =>
        Tree().Descendants().Any(n => n.Tag == "button" && n.Text.Contains(label, StringComparison.Ordinal));

    /// <summary>Type into the TextField/field whose label starts with <paramref name="label"/>.</summary>
    public async Task TypeAsync(string label, string value, int nth = 0)
    {
        var labels = Tree().Descendants().Where(n => n.Tag == "label" && n.Text.StartsWith(label, StringComparison.Ordinal)).ToList();
        if (labels.Count <= nth) throw new InvalidOperationException($"No field '{label}'. Page text: {Truncate(Text)}");
        var input = labels[nth].Descendants().First(d => d.Events.ContainsKey("oninput") || d.Events.ContainsKey("onchange"));
        var evt = input.Events.ContainsKey("oninput") ? "oninput" : "onchange";
        await DispatchAsync(input.Events[evt], new ChangeEventArgs { Value = value });
    }

    /// <summary>Set a CheckField (label) or a select/checkbox via its change handler.</summary>
    public async Task ChangeAsync(string label, object value, int nth = 0)
    {
        var labels = Tree().Descendants().Where(n => n.Tag == "label" && n.Text.Contains(label, StringComparison.Ordinal)).ToList();
        if (labels.Count <= nth) throw new InvalidOperationException($"No field '{label}'. Page text: {Truncate(Text)}");
        var input = labels[nth].Descendants().First(d => d.Events.ContainsKey("onchange"));
        await DispatchAsync(input.Events["onchange"], new ChangeEventArgs { Value = value });
    }

    /// <summary>Fire onchange on the nth element with a change handler of the given tag (select / checkbox / file).</summary>
    public async Task ChangeTagAsync(string tag, object value, int nth = 0)
    {
        var el = Tree().Descendants().Where(n => n.Tag == tag && n.Events.ContainsKey("onchange")).ToList();
        if (el.Count <= nth) throw new InvalidOperationException($"No <{tag}> with onchange (nth={nth}). Page text: {Truncate(Text)}");
        await DispatchAsync(el[nth].Events["onchange"], new ChangeEventArgs { Value = value });
    }


    /// <summary>Click the element labelled <paramref name="label"/> inside the smallest container (of the tag) that contains <paramref name="containerText"/> AND such an element.</summary>
    public async Task ClickInAsync(string containerTag, string containerText, string label)
    {
        var containers = Tree().Descendants()
            .Where(n => n.Tag == containerTag && n.Text.Contains(containerText, StringComparison.OrdinalIgnoreCase))
            .OrderBy(n => n.Text.Length).ToList();
        if (containers.Count == 0)
            throw new InvalidOperationException($"No <{containerTag}> containing '{containerText}'. Page text: {Truncate(Text)}");
        foreach (var c in containers)
        {
            var b = c.Descendants().Where(n => n.Events.ContainsKey("onclick") && n.Text.Contains(label, StringComparison.OrdinalIgnoreCase))
                .OrderBy(n => n.Text.Length).FirstOrDefault();
            if (b is null) continue;
            await DispatchAsync(b.Events["onclick"], new MouseEventArgs());
            return;
        }
        throw new InvalidOperationException($"No '{label}' control in any <{containerTag}> containing '{containerText}'.");
    }

    /// <summary>Fire onchange on the nth change-capable element inside the smallest container containing the text.</summary>
    public async Task ChangeInAsync(string containerTag, string containerText, object value, int nth = 0)
    {
        var containers = Tree().Descendants()
            .Where(n => n.Tag == containerTag && n.Text.Contains(containerText, StringComparison.OrdinalIgnoreCase))
            .OrderBy(n => n.Text.Length).ToList();
        foreach (var c in containers)
        {
            var els = c.Descendants().Where(n => n.Events.ContainsKey("onchange")).ToList();
            if (els.Count <= nth) continue;
            await DispatchAsync(els[nth].Events["onchange"], new ChangeEventArgs { Value = value });
            return;
        }
        throw new InvalidOperationException($"No change control in <{containerTag}> containing '{containerText}'. Page text: {Truncate(Text)}");
    }

    /// <summary>Click the row (element with onclick) itself.</summary>
    public async Task ClickRowAsync(string tag, string containerText)
    {
        var c = Tree().Descendants()
            .Where(n => n.Tag == tag && n.Events.ContainsKey("onclick") && n.Text.Contains(containerText, StringComparison.Ordinal))
            .OrderBy(n => n.Text.Length).FirstOrDefault()
            ?? throw new InvalidOperationException($"No clickable <{tag}> containing '{containerText}'. Page text: {Truncate(Text)}");
        await DispatchAsync(c.Events["onclick"], new MouseEventArgs());
    }

    /// <summary>Raise an arbitrary event (e.g. onkeyup) on the input inside the label that starts with <paramref name="label"/>.</summary>
    public async Task FireAsync(string label, string evt, EventArgs args)
    {
        var l = Tree().Descendants().FirstOrDefault(n => n.Tag == "label" && n.Text.StartsWith(label, StringComparison.Ordinal))
            ?? throw new InvalidOperationException($"No field '{label}'.");
        var el = l.Descendants().First(d => d.Events.ContainsKey(evt));
        await DispatchAsync(el.Events[evt], args);
    }

    /// <summary>Raise an event on a specific node previously found in the tree.</summary>
    public Task FireOnAsync(PageANode node, string evt, EventArgs args) => DispatchAsync(node.Events[evt], args);

    /// <summary>Type into an input located by (part of) its placeholder.</summary>
    public async Task TypePlaceholderAsync(string placeholder, string value)
    {
        var el = Tree().Descendants().FirstOrDefault(n => n.Tag == "input" && (n.Attr("placeholder")?.Contains(placeholder, StringComparison.Ordinal) ?? false))
            ?? throw new InvalidOperationException($"No input with placeholder '{placeholder}'.");
        var evt = el.Events.ContainsKey("oninput") ? "oninput" : "onchange";
        await DispatchAsync(el.Events[evt], new ChangeEventArgs { Value = value });
    }

    private static string Truncate(string s) => s.Length > 1500 ? s[..1500] + "…" : s;

}

/// <summary>
/// One signed-in "browser tab": a DI scope with the user's authentication state and a navigation
/// manager initialised, plus a renderer to drive pages.
/// </summary>
public sealed class PageAHost : IAsyncDisposable
{
    private static readonly object Gate = new();
    private static WebApplicationFactory<Program>? _factory;
    private static WebApplicationFactory<Program>? _source;

    private readonly IServiceScope _scope;
    public PageARenderer Renderer { get; }
    public IServiceProvider Services => _scope.ServiceProvider;
    public FakeNav Nav { get; }

    private PageAHost(IServiceScope scope, PageARenderer renderer, FakeNav nav)
    {
        _scope = scope; Renderer = renderer; Nav = nav;
    }

    public sealed record FakeNav(NavigationManager Manager)
    {
        public string Uri => Manager.Uri;
    }

    private static WebApplicationFactory<Program> StubbedFactory(WebApplicationFactory<Program> source)
    {
        lock (Gate)
        {
            if (_factory is null || !ReferenceEquals(_source, source))
            {
                _source = source;
                _factory = source.WithWebHostBuilder(b => b.ConfigureTestServices(s =>
                {
                    s.AddScoped<IJSRuntime, PageAJsRuntime>();
                }));
            }
            return _factory;
        }
    }

    public static async Task<PageAHost> ForAsync(DatabaseFixture fx, User? user, string path = "/")
    {
        var factory = StubbedFactory(fx.Factory!);
        var scope = factory.Services.CreateScope();
        var sp = scope.ServiceProvider;

        var principal = user is null
            ? new ClaimsPrincipal(new ClaimsIdentity())
            : new ClaimsPrincipal(new ClaimsIdentity(
            [
                new Claim(ClaimTypes.Name, user.Login),
                new Claim(ClaimTypes.NameIdentifier, user.Login),
                new Claim("urn:tamp.findings:userId", user.Id.ToString()),
            ], "PageA"));
        ((IHostEnvironmentAuthenticationStateProvider)sp.GetRequiredService<AuthenticationStateProvider>())
            .SetAuthenticationState(Task.FromResult(new AuthenticationState(principal)));

        var nav = sp.GetRequiredService<NavigationManager>();
        ((IHostEnvironmentNavigationManager)nav).Initialize("http://localhost/", "http://localhost" + path);

        var renderer = new PageARenderer(sp);
        await Task.CompletedTask;
        return new PageAHost(scope, renderer, new FakeNav(nav));
    }

    public Task<PageARenderer> OpenAsync<TPage>(params (string Name, object? Value)[] parameters) where TPage : IComponent
    {
        return OpenAsync(typeof(TPage), parameters);
    }

    public async Task<PageARenderer> OpenAsync(Type page, params (string Name, object? Value)[] parameters)
    {
        await Renderer.StartAsync(page, parameters.ToDictionary(p => p.Name, p => p.Value));
        return Renderer;
    }

    /// <summary>Dispose the scope's DbContext so every query throws, exercising a page's "could not load" branch.</summary>
    public void BreakDatabase() => Services.GetRequiredService<Tamp.Findings.Data.FindingsDbContext>().Dispose();

    /// <summary>Open a page and swallow any failure (used with <see cref="BreakDatabase"/>); returns the page text.</summary>
    public async Task<string> OpenLenientAsync(Type page, params (string Name, object? Value)[] parameters)
    {
        try { await Renderer.StartAsync(page, parameters.ToDictionary(p => p.Name, p => p.Value)); }
        catch (Exception) { /* the page failed to load; that is the point */ }
        try { return Renderer.Text; } catch (Exception) { return ""; }
    }

    /// <summary>Open a component inside CascadingAuthenticationState (for AuthorizeView users such as the layout).</summary>
    public Task<PageARenderer> OpenCascadedAsync<TComponent>(params (string Name, object? Value)[] parameters) where TComponent : IComponent
    {
        return Renderer.StartAsync(typeof(PageACascade), new Dictionary<string, object?>
        {
            ["Inner"] = typeof(TComponent),
            ["Params"] = parameters.ToDictionary(p => p.Name, p => p.Value),
        }).ContinueWith(_ => Renderer, TaskScheduler.Default);
    }

    public async ValueTask DisposeAsync()
    {
        Renderer.Dispose();
        if (_scope is IAsyncDisposable ad) await ad.DisposeAsync(); else _scope.Dispose();
    }
}

/// <summary>JS interop stub: every call returns default.</summary>
public sealed class PageAJsRuntime : IJSRuntime
{
    public ValueTask<TValue> InvokeAsync<TValue>(string identifier, object?[]? args) => new(default(TValue)!);

    public ValueTask<TValue> InvokeAsync<TValue>(string identifier, CancellationToken cancellationToken, object?[]? args) =>
        new(default(TValue)!);
}

/// <summary>Wraps a component in CascadingAuthenticationState.</summary>
public sealed class PageACascade : ComponentBase
{
    [Parameter] public Type Inner { get; set; } = typeof(object);
    [Parameter] public Dictionary<string, object?> Params { get; set; } = [];

    protected override void BuildRenderTree(Microsoft.AspNetCore.Components.Rendering.RenderTreeBuilder builder)
    {
        builder.OpenComponent<CascadingAuthenticationState>(0);
        builder.AddAttribute(1, "ChildContent", (RenderFragment)(b =>
        {
            b.OpenComponent(0, Inner);
            var i = 1;
            foreach (var kv in Params) b.AddAttribute(i++, kv.Key, kv.Value);
            b.CloseComponent();
        }));
        builder.CloseComponent();
    }
}
