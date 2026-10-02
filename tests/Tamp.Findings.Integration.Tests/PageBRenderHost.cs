#pragma warning disable BL0006 // RenderTree types: a test-only renderer is the whole point of this file
using System.Security.Claims;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Infrastructure;
using Microsoft.AspNetCore.Components.RenderTree;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.JSInterop;
using Tamp.Findings.Api.Authentication;

namespace Tamp.Findings.Integration.Tests;

/// <summary>
/// A minimal, in-process Blazor "browser" for the PageB tests: it instantiates a routable component
/// directly (no HTTP, no SignalR circuit), renders it against the real host's services and a real
/// database, and lets a test drive it — click a button by its text, type into an input, then read
/// back the rendered text. That is the only way to reach the page's event handlers (dialogs,
/// save/delete/transition flows), which a server-prerender GET never executes.
/// </summary>
public sealed class PageBRenderHost : IAsyncDisposable
{
    private readonly IServiceScope _scope;
    private readonly TestRenderer _renderer;
    private readonly int _rootId;

    public List<Exception> Errors => _renderer.Errors;

    private readonly TestNavigation _nav;

    private readonly OverrideProvider _provider;

    private PageBRenderHost(IServiceScope scope, TestRenderer renderer, int rootId, TestNavigation nav, OverrideProvider provider)
    {
        _provider = provider;
        _nav = nav;
        _scope = scope;
        _renderer = renderer;
        _rootId = rootId;
    }

    /// <summary>Render <typeparamref name="TPage"/> as the given PageB user (Admin / Lead / Viewer).</summary>
    public static async Task<PageBRenderHost> RenderAsync<TPage>(
        PageBWorld world, IDictionary<string, object?> parameters, string who = PageBWorld.Admin, string path = "/")
        where TPage : IComponent
    {
        var scope = world.Host.Services.CreateScope();
        var (id, login, isAdmin) = who switch
        {
            PageBWorld.Lead => (PageBWorld.LeadId, "pageb-lead", false),
            PageBWorld.Viewer => (PageBWorld.ViewerId, "pageb-viewer", false),
            PageBWorld.Iso => (PageBWorld.IsoId, "pageb-iso", false),
            _ => (PageBWorld.AdminId, "pageb-admin", true),
        };
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim(ClaimTypes.Name, login),
            new Claim(ClaimTypes.NameIdentifier, id.ToString()),
            new Claim(AuthExtensions.TampUserIdClaim, id.ToString()),
            new Claim(AuthExtensions.TampIsAdminClaim, isAdmin.ToString()),
        ], "PageBTest"));

        var sp = scope.ServiceProvider;
        ((IHostEnvironmentAuthenticationStateProvider)sp.GetRequiredService<AuthenticationStateProvider>())
            .SetAuthenticationState(Task.FromResult(new AuthenticationState(principal)));
        // The scope's own NavigationManager feeds [SupplyParameterFromQuery]; initialise it by
        // reflection (the public initialiser interface is not reachable from a test assembly).
        var realNav = sp.GetRequiredService<NavigationManager>();
        typeof(NavigationManager).GetMethod("Initialize", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Public, [typeof(string), typeof(string)])!
            .Invoke(realNav, ["http://localhost/", "http://localhost" + path]);
        var nav = new TestNavigation();
        nav.Setup("http://localhost/", "http://localhost" + path);
        var provider = new OverrideProvider(sp, nav);
        var renderer = new TestRenderer(provider, sp.GetRequiredService<ILoggerFactory>());
        var rootId = await renderer.RenderRootAsync(typeof(TPage), parameters);
        var host = new PageBRenderHost(scope, renderer, rootId, nav, provider);
        await host.PumpVirtualizeAsync();
        return host;
    }

    /// <summary>The visible text of the whole page, whitespace-collapsed.</summary>
    public string Text => Snapshot().Text;

    public IReadOnlyList<Node> Elements => Snapshot().Elements;

    public bool Contains(string text) => Text.Contains(text, StringComparison.Ordinal);

    public string Navigated => _nav.Last ?? "";

    private Snap Snapshot()
    {
        var snap = new Snap();
        _renderer.Walk(_rootId, snap);
        return snap;
    }

    /// <summary>
    /// Click the LAST enabled clickable element whose text contains <paramref name="text"/>
    /// (last, so dialog buttons that render after the page's own win). Returns false when absent.
    /// </summary>
    public async Task<bool> ClickAsync(string text, int skip = 0)
    {
        var matches = Snapshot().Elements
            .Where(e => e.Handlers.ContainsKey("onclick") && !e.Attrs.ContainsKey("disabled")
                        && e.Text.Contains(text, StringComparison.Ordinal))
            .ToList();
        if (matches.Count - 1 - skip < 0) return false;
        var target = matches[matches.Count - 1 - skip];
        await DispatchAsync(target.Handlers["onclick"], new MouseEventArgs());
        return true;
    }

    /// <summary>Click the nth (0-based) clickable element satisfying a predicate.</summary>
    public async Task<bool> ClickWhereAsync(Func<Node, bool> predicate, int nth = 0)
    {
        var matches = Snapshot().Elements
            .Where(e => e.Handlers.ContainsKey("onclick") && !e.Attrs.ContainsKey("disabled") && predicate(e)).ToList();
        if (nth >= matches.Count) return false;
        await DispatchAsync(matches[nth].Handlers["onclick"], new MouseEventArgs());
        return true;
    }

    /// <summary>Set an input/textarea/select whose placeholder, label text or order matches.</summary>
    public async Task<bool> TypeAsync(Func<Node, bool> predicate, string value, int nth = 0)
    {
        var matches = Snapshot().Elements
            .Where(e => e.Name is "input" or "textarea" or "select"
                        && (e.Handlers.ContainsKey("onchange") || e.Handlers.ContainsKey("oninput")) && predicate(e)).ToList();
        if (nth >= matches.Count) return false;
        var h = matches[nth].Handlers;
        await DispatchAsync(h.TryGetValue("onchange", out var c) ? c : h["oninput"], new ChangeEventArgs { Value = value });
        return true;
    }

    /// <summary>Set the editable control inside the field whose label text contains <paramref name="label"/>.</summary>
    public Task<bool> TypeLabelAsync(string label, string value, int nth = 0) =>
        TypeAsync(e => e.Label.Contains(label, StringComparison.Ordinal), value, nth);

    /// <summary>The nth editable control in document order (any input / textarea / select).</summary>
    public async Task<bool> TypeNthAsync(int index, string value)
    {
        var inputs = Snapshot().Elements
            .Where(e => e.Name is "input" or "textarea" or "select"
                        && (e.Handlers.ContainsKey("onchange") || e.Handlers.ContainsKey("oninput"))).ToList();
        if (index >= inputs.Count) return false;
        var h = inputs[index].Handlers;
        await DispatchAsync(h.TryGetValue("onchange", out var c) ? c : h["oninput"], new ChangeEventArgs { Value = value });
        return true;
    }

    public async Task<bool> CheckNthAsync(int index, bool value)
    {
        var inputs = Snapshot().Elements
            .Where(e => e.Name == "input" && e.Attrs.TryGetValue("type", out var t) && Equals(t, "checkbox")
                        && e.Handlers.ContainsKey("onchange")).ToList();
        if (index >= inputs.Count) return false;
        await DispatchAsync(inputs[index].Handlers["onchange"], new ChangeEventArgs { Value = value });
        return true;
    }

    public int InputCount => Snapshot().Elements.Count(e => e.Name is "input" or "textarea" or "select"
        && (e.Handlers.ContainsKey("onchange") || e.Handlers.ContainsKey("oninput")));

    private async Task DispatchAsync(ulong handlerId, EventArgs args)
    {
        try
        {
            await _renderer.Dispatcher.InvokeAsync(() => _renderer.DispatchEventAsync(handlerId, null, args));
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _renderer.Errors.Add(ex);
        }
        await PumpVirtualizeAsync();
    }

    /// <summary>Tell every live &lt;Virtualize&gt; that a tall viewport is visible, so its rows render.</summary>
    private async Task PumpVirtualizeAsync()
    {
        object[] refs;
        lock (_provider.Js.Virtualizers) refs = _provider.Js.Virtualizers.ToArray();
        foreach (var reference in refs)
        {
            var target = reference.GetType().GetProperty("Value")?.GetValue(reference);
            var method = target?.GetType().GetMethod("OnSpacerAfterVisible");
            if (method is null) continue;
            try
            {
                await _renderer.Dispatcher.InvokeAsync(async () =>
                {
                    // Void in current framework versions, ValueTask / Task in others.
                    switch (method.Invoke(target, [0f, 0f, 4000f]))
                    {
                        case ValueTask vt: await vt; break;
                        case Task t: await t; break;
                    }
                });
            }
            catch (ObjectDisposedException) { }
            catch (ArgumentException) { }
        }
    }

    public async ValueTask DisposeAsync()
    {
        _renderer.Dispose();
        if (_scope is IAsyncDisposable ad) await ad.DisposeAsync(); else _scope.Dispose();
    }

    // ---- model ---------------------------------------------------------------

    public sealed class Node
    {
        public required string Name { get; init; }
        public Dictionary<string, object?> Attrs { get; } = new();
        public Dictionary<string, ulong> Handlers { get; } = new();
        public string Text { get; set; } = "";
        public string Label { get; set; } = "";
        public string Class => Attrs.TryGetValue("class", out var c) ? c?.ToString() ?? "" : "";
        public string Attr(string n) => Attrs.TryGetValue(n, out var v) ? v?.ToString() ?? "" : "";
    }

    public sealed class Snap
    {
        public List<Node> Elements { get; } = [];
        public string Text { get; set; } = "";
    }

    // ---- plumbing ------------------------------------------------------------

    private sealed class TestRenderer(IServiceProvider sp, ILoggerFactory lf) : Renderer(sp, lf)
    {
        public List<Exception> Errors { get; } = [];
        public override Dispatcher Dispatcher { get; } = Dispatcher.CreateDefault();

        protected override void HandleException(Exception exception) => Errors.Add(exception);

        // Pages declare @rendermode InteractiveServer; this host IS the interactive runtime, so just
        // create the component.
        protected override IComponent ResolveComponentForRenderMode(
            Type componentType, int? parentComponentId, IComponentActivator componentActivator, IComponentRenderMode renderMode) =>
            componentActivator.CreateInstance(componentType);

        protected override Task UpdateDisplayAsync(in RenderBatch renderBatch) => Task.CompletedTask;

        public Task<int> RenderRootAsync(Type type, IDictionary<string, object?> parameters) =>
            Dispatcher.InvokeAsync(async () =>
            {
                var component = InstantiateComponent(type);
                var id = AssignRootComponentId(component);
                await RenderRootComponentAsync(id, ParameterView.FromDictionary(parameters));
                return id;
            });

        public void Walk(int componentId, Snap snap)
        {
            var frames = GetCurrentRenderTreeFrames(componentId);
            snap.Text = Collapse(WalkFrames(frames, snap));
        }

        private string WalkFrames(ArrayRange<RenderTreeFrame> frames, Snap snap)
        {
            var sb = new System.Text.StringBuilder();
            var arr = frames.Array;
            Node? label = null;
            var labelEnd = -1;
            for (var i = 0; i < frames.Count; i++)
            {
                ref var f = ref arr[i];
                switch (f.FrameType)
                {
                    case RenderTreeFrameType.Element:
                    {
                        var node = new Node { Name = f.ElementName };
                        var end = i + f.ElementSubtreeLength;
                        var j = i + 1;
                        for (; j < end && arr[j].FrameType == RenderTreeFrameType.Attribute; j++)
                        {
                            ref var a = ref arr[j];
                            if (a.AttributeEventHandlerId != 0) node.Handlers[a.AttributeName] = a.AttributeEventHandlerId;
                            else node.Attrs[a.AttributeName] = a.AttributeValue;
                        }
                        // The element's own text, including text rendered by child components.
                        var inner = new System.Text.StringBuilder();
                        CollectText(arr, j, end, inner, snap: null);
                        node.Text = Collapse(inner.ToString());
                        if (node.Name == "label") { label = node; labelEnd = end; }
                        else if (label is not null && i < labelEnd) node.Label = label.Text;
                        snap.Elements.Add(node);
                        break;
                    }
                    case RenderTreeFrameType.Text:
                        sb.Append(f.TextContent).Append(' ');
                        break;
                    case RenderTreeFrameType.Markup:
                        sb.Append(PlainText(f.MarkupContent)).Append(' ');
                        break;
                    case RenderTreeFrameType.Component:
                    {
                        var child = Walk2(f.ComponentId, snap);
                        sb.Append(child).Append(' ');
                        i += f.ComponentSubtreeLength - 1;
                        break;
                    }
                }
            }
            return sb.ToString();
        }

        private string Walk2(int componentId, Snap snap) =>
            WalkFrames(GetCurrentRenderTreeFrames(componentId), snap);

        private void CollectText(RenderTreeFrame[] arr, int from, int to, System.Text.StringBuilder sb, Snap? snap)
        {
            for (var i = from; i < to; i++)
            {
                ref var f = ref arr[i];
                switch (f.FrameType)
                {
                    case RenderTreeFrameType.Text: sb.Append(f.TextContent).Append(' '); break;
                    case RenderTreeFrameType.Markup: sb.Append(PlainText(f.MarkupContent)).Append(' '); break;
                    case RenderTreeFrameType.Component:
                    {
                        var childFrames = GetCurrentRenderTreeFrames(f.ComponentId);
                        CollectText(childFrames.Array, 0, childFrames.Count, sb, snap);
                        i += f.ComponentSubtreeLength - 1;
                        break;
                    }
                }
            }
        }

        private static string PlainText(string markup) =>
            System.Net.WebUtility.HtmlDecode(System.Text.RegularExpressions.Regex.Replace(markup, "<[^>]*>", " "));

        private static string Collapse(string s) => System.Text.RegularExpressions.Regex.Replace(s, @"\s+", " ").Trim();
    }

    /// <summary>
    /// Wraps the scope so components get a no-op JS runtime (no circuit here) and a navigation
    /// manager that records where it was sent instead of throwing.
    /// </summary>
    private sealed class OverrideProvider(IServiceProvider inner, NavigationManager nav) : IServiceProvider, ISupportRequiredService
    {
        public FakeJs Js { get; } = new();

        public object? GetService(Type serviceType) =>
            serviceType == typeof(IJSRuntime) ? Js
            : serviceType == typeof(NavigationManager) ? nav
            : inner.GetService(serviceType);

        public object GetRequiredService(Type serviceType) =>
            GetService(serviceType) ?? throw new InvalidOperationException("No service for " + serviceType);
    }

    private sealed class FakeJs : IJSRuntime
    {
        // <Virtualize> only renders items once the browser reports a viewport. Capture the interop
        // object it hands to Blazor._internal.Virtualize.init so the host can play the browser's part.
        public List<object> Virtualizers { get; } = [];

        public ValueTask<TValue> InvokeAsync<TValue>(string identifier, object?[]? args)
        {
            if (identifier.EndsWith("Virtualize.init", StringComparison.Ordinal) && args is { Length: > 0 } && args[0] is { } reference)
                lock (Virtualizers) Virtualizers.Add(reference);
            return ValueTask.FromResult(default(TValue)!);
        }

        public ValueTask<TValue> InvokeAsync<TValue>(string identifier, CancellationToken cancellationToken, object?[]? args) =>
            InvokeAsync<TValue>(identifier, args);
    }

    private sealed class TestNavigation : NavigationManager
    {
        public string? Last { get; private set; }
        public void Setup(string baseUri, string uri) => Initialize(baseUri, uri);
        protected override void NavigateToCore(string uri, NavigationOptions options) => Last = uri;
    }
}
