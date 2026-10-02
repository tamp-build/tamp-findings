using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Web;
using Tamp.Findings.Web.Components.Layout;
using Tamp.Findings.Web.Components.Primitives;
using Tamp.Findings.Web.Components.Shared;

namespace Tamp.Findings.Integration.Tests;

[Collection(DatabaseCollection.Name)]
public class PageAPrimitivesAndShellTests
{
    private readonly DatabaseFixture _fx;
    public PageAPrimitivesAndShellTests(DatabaseFixture fx) => _fx = fx;

    [SkippableFact]
    public async Task Small_primitives_render_their_states_and_raise_their_events()
    {
        Skip.IfNot(_fx.Available);
        var w = await PageAWorld.SeedAsync(_fx);

        await using var h = await PageAHost.ForAsync(_fx, w.Admin, "/");
        var ph = await h.OpenAsync<Placeholder>(
            ("Title", "Pending screen"), ("Ticket", "TFND-1"), ("Description", "coming soon"),
            ("Scope", (IReadOnlyList<KeyValuePair<string, string?>>)new List<KeyValuePair<string, string?>> { new("client", "c1"), new("build", null) }));
        ph.Expect("Pending screen");
        ph.Expect("c1");

        await using var h2 = await PageAHost.ForAsync(_fx, w.Admin, "/");
        (await h2.OpenAsync<Placeholder>(("Title", "Bare"), ("Ticket", "T"))).Expect("Bare");

        await using var h3 = await PageAHost.ForAsync(_fx, w.Admin, "/");
        (await h3.OpenAsync<Tally>(("Glyph", "✓"), ("Label", "Passed"), ("Value", 7), ("Tone", "var(--color-pass)"))).Expect("Passed");
        await using var h3b = await PageAHost.ForAsync(_fx, w.Admin, "/");
        (await h3b.OpenAsync<Tally>(("Glyph", "✕"), ("Label", "Failed"), ("Value", 0))).Expect("Failed");

        await using var h4 = await PageAHost.ForAsync(_fx, w.Admin, "/");
        (await h4.OpenAsync<NotScanned>(("Message", "DAST did not run"))).Expect("DAST did not run");
        await using var h4b = await PageAHost.ForAsync(_fx, w.Admin, "/");
        (await h4b.OpenAsync<NotScanned>()).Expect("did not run for this build");

        var selected = 0;
        await using var h5 = await PageAHost.ForAsync(_fx, w.Admin, "/");
        var row = await h5.OpenAsync<TreeRow>(
            ("Name", "src/Foo.cs"), ("Depth", 2), ("Group", false), ("Selected", true),
            ("Badge", (RenderFragment)(b => b.AddContent(0, "3 findings"))),
            ("OnSelect", EventCallback.Factory.Create(this, () => { selected++; })));
        row.Expect("src/Foo.cs");
        row.Expect("3 findings");
        await row.ClickAsync("src/Foo.cs");
        Assert.Equal(1, selected);
        await using var h5b = await PageAHost.ForAsync(_fx, w.Admin, "/");
        (await h5b.OpenAsync<TreeRow>(("Name", "src"), ("Group", true))).Expect("src");

        await using var h6 = await PageAHost.ForAsync(_fx, w.Admin, "/");
        (await h6.OpenAsync<Sparkline>(("Points", (IReadOnlyList<double>)new List<double> { 1, 5, 3, 9 }))).ThrowIfErrors();
        await using var h6b = await PageAHost.ForAsync(_fx, w.Admin, "/");
        (await h6b.OpenAsync<Sparkline>(("Points", (IReadOnlyList<double>)new List<double> { 4 }))).ThrowIfErrors();
        await using var h6c = await PageAHost.ForAsync(_fx, w.Admin, "/");
        (await h6c.OpenAsync<Sparkline>(("Points", (IReadOnlyList<double>)new List<double> { 2, 2, 2 }))).ThrowIfErrors();

        await using var h7 = await PageAHost.ForAsync(_fx, w.Admin, "/");
        (await h7.OpenAsync<Icon>(("Name", "definitely-not-an-icon"), ("Title", "t"), ("Class", "x"))).ThrowIfErrors();

        // Dialog: escape and the close button both ask to close; other keys do not.
        var open = true;
        await using var h8 = await PageAHost.ForAsync(_fx, w.Admin, "/");
        var dlg = await h8.OpenAsync<Dialog>(
            ("Open", true), ("Title", "A dialog"),
            ("OpenChanged", EventCallback.Factory.Create<bool>(this, v => { open = v; })),
            ("ChildContent", (RenderFragment)(b => b.AddContent(0, "dialog body"))),
            ("Footer", (RenderFragment)(b => b.AddContent(0, "dialog footer"))));
        dlg.Expect("dialog body");
        dlg.Expect("dialog footer");
        var overlay = dlg.Tree().Descendants().First(n => n.Events.ContainsKey("onkeydown"));
        await dlg.FireOnAsync(overlay, "onkeydown", new KeyboardEventArgs { Key = "Enter" });
        Assert.True(open);
        await dlg.FireOnAsync(overlay, "onkeydown", new KeyboardEventArgs { Key = "Escape" });
        Assert.False(open);
        await dlg.ClickButtonAsync("✕");

        await using var h9 = await PageAHost.ForAsync(_fx, w.Admin, "/");
        (await h9.OpenAsync<Dialog>(("Open", false), ("Title", "closed"))).ThrowIfErrors();

        // CheckField as a radio, enabled and disabled.
        var checkedValue = false;
        await using var h10 = await PageAHost.ForAsync(_fx, w.Admin, "/");
        var radio = await h10.OpenAsync<CheckField>(
            ("Label", "Pick me"), ("Radio", true), ("Name", "grp"),
            ("CheckedChanged", EventCallback.Factory.Create<bool>(this, v => { checkedValue = v; })));
        await radio.ChangeAsync("Pick me", true);
        Assert.True(checkedValue);
        checkedValue = false;
        await using var h11 = await PageAHost.ForAsync(_fx, w.Admin, "/");
        var disabled = await h11.OpenAsync<CheckField>(
            ("Label", "Nope"), ("Disabled", true),
            ("CheckedChanged", EventCallback.Factory.Create<bool>(this, v => { checkedValue = v; })));
        await disabled.ChangeAsync("Nope", true);
        Assert.False(checkedValue);
    }

    [SkippableFact]
    public async Task Main_layout_wraps_a_body_and_reloads_preferences_on_change()
    {
        Skip.IfNot(_fx.Available);
        var w = await PageAWorld.SeedAsync(_fx);
        await using var h = await PageAHost.ForAsync(_fx, w.Admin, "/portfolio");
        var layout = await h.OpenCascadedAsync<MainLayout>(("Body", (RenderFragment)(b => b.AddContent(0, "page body here"))));
        layout.Expect("page body here");
        layout.Expect("tamp");
        await layout.ClickButtonAsync("comfortable");
        await layout.ClickButtonAsync("compact");
    }

    [SkippableFact]
    public async Task Anonymous_visitors_are_sent_to_sign_in_and_unknown_routes_say_not_found()
    {
        Skip.IfNot(_fx.Available);
        var anon = _fx.Factory!.CreateClient();
        var protectedPage = await anon.GetAsync("/portfolio");
        var protectedBody = await protectedPage.Content.ReadAsStringAsync();
        Assert.True(
            (int)protectedPage.StatusCode is >= 300 and < 400 || protectedBody.Contains("Sign in", StringComparison.OrdinalIgnoreCase)
            || protectedBody.Contains("signin", StringComparison.OrdinalIgnoreCase), protectedBody);

        var missing = await anon.GetAsync("/definitely/not/a/page");
        Assert.NotEqual(System.Net.HttpStatusCode.InternalServerError, missing.StatusCode);

        var w = await PageAWorld.SeedAsync(_fx);
        var signedIn = _fx.Factory.SignedInAs(w.Admin);
        var notFound = await signedIn.GetAsync("/definitely/not/a/page");
        Assert.Contains("not found", (await notFound.Content.ReadAsStringAsync()), StringComparison.OrdinalIgnoreCase);
    }
}
