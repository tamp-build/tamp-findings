using System.Net;
using Tamp.Findings.Web.Routing;

namespace Tamp.Findings.Api.Tests;

// The URL scheme is the headline fix of TFND-40: navigation used to be
// useState, so nothing was addressable and nothing survived a reload.
//
// A link that 404s today and works next month is indistinguishable from a bug,
// so every route in the design scheme is registered before its screen exists —
// and these assert that every one of them resolves.
public class RoutingTests : IClassFixture<TestApiFactory>
{
    private readonly TestApiFactory _factory;

    public RoutingTests(TestApiFactory factory) => _factory = factory;

    // Straight from docs/redesign/README.md "URL scheme".
    [Theory]
    [InlineData("/portfolio")]
    [InlineData("/c/brewingcoder/p/tamp/build/179fe8b")]
    [InlineData("/c/brewingcoder/p/tamp/build/179fe8b/sast")]
    [InlineData("/c/brewingcoder/p/tamp/build/179fe8b/dast")]
    [InlineData("/c/brewingcoder/p/tamp/build/179fe8b/sbom")]
    [InlineData("/c/brewingcoder/p/tamp/build/179fe8b/coverage")]
    [InlineData("/c/brewingcoder/p/tamp/build/179fe8b/tests")]
    [InlineData("/c/brewingcoder/p/tamp/build/179fe8b/attestation")]
    [InlineData("/c/brewingcoder/p/tamp/poam")]
    [InlineData("/c/brewingcoder/p/tamp/poam/42")]
    [InlineData("/c/brewingcoder/p/tamp/vex")]
    [InlineData("/c/brewingcoder/p/tamp/settings/policy")]
    [InlineData("/c/brewingcoder/p/tamp/settings/keys")]
    [InlineData("/system")]
    [InlineData("/system/users")]
    [InlineData("/system/audit")]
    public async Task Every_route_in_the_design_scheme_resolves(string path)
    {
        var client = _factory.CreateClient();

        var resp = await client.GetAsync(path);

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task An_explorer_selection_may_contain_slashes()
    {
        // Selections are usually source paths, so the route captures them as a
        // catch-all. Without that, ".../sast/src/Api/Program.cs" would fail to
        // match and every SAST deep link into a nested file would break.
        var client = _factory.CreateClient();

        var resp = await client.GetAsync("/c/brewingcoder/p/tamp/build/179fe8b/sast/src/Api/IngestEndpoints.cs");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task Attestation_wins_over_the_explorer_spine_parameter()
    {
        // Both routes have the same segment count under /build/{sha}/. A
        // literal beats a parameter in Blazor's route table, so this needs no
        // constraint — but if that ever changes, the attestation would start
        // rendering as an explorer spine named "attestation".
        // Signed in, because both routes render the same NotAuthorized
        // fragment to an anonymous visitor — the assertion would be vacuous.
        var client = _factory.CreateSignedIn();

        var body = await client.GetStringAsync("/c/brewingcoder/p/tamp/build/179fe8b/attestation");

        Assert.Contains("Attestation", body, StringComparison.Ordinal);
        Assert.DoesNotContain("Unknown spine", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_valid_spine_renders_the_explorer_and_an_unknown_one_says_so()
    {
        var client = _factory.CreateSignedIn();

        var sast = await client.GetStringAsync("/c/brewingcoder/p/tamp/build/179fe8b/sast");
        var bogus = await client.GetStringAsync("/c/brewingcoder/p/tamp/build/179fe8b/bogus");

        // Asserted on the SPINE VALIDATION rather than on the screen's title:
        // this suite has no database, so a valid spine renders the Unavailable
        // state, and asserting a title here would only be testing which error
        // path ran.
        Assert.DoesNotContain("Unknown spine", sast, StringComparison.Ordinal);

        // A bad spine is a broken link, not an empty screen — and it is
        // rejected BEFORE any database is touched, which is why this half
        // still asserts real content.
        Assert.Contains("Unknown spine", bogus, StringComparison.Ordinal);
        Assert.Contains("Go to the SAST spine", bogus, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_unknown_system_panel_says_so_rather_than_rendering_empty()
    {
        var client = _factory.CreateSignedIn();

        var body = await client.GetStringAsync("/system/bogus");

        Assert.Contains("Unknown panel", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_unrouted_path_reaches_blazors_own_not_found()
    {
        // This assertion is the INVERSE of what it was before TFND-128, and
        // deliberately so. While the React SPA existed, Blazor had to leave
        // unknown paths alone or it would shadow index.html. Now that the
        // fallback is gone, an unmatched URL must reach the catch-all page —
        // otherwise the reader gets a bare ASP.NET 404 with no shell and
        // nowhere to click.
        var client = _factory.CreateSignedIn();

        var body = await client.GetStringAsync("/definitely-not-a-route");

        Assert.Contains("Nothing at this address", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_catch_all_page_does_not_leak_the_shell_to_an_anonymous_visitor()
    {
        // A page that matches everything is the easiest place to accidentally
        // publish the application chrome to someone who has not signed in.
        var client = _factory.CreateClient();

        var body = await client.GetStringAsync("/definitely-not-a-route");

        Assert.DoesNotContain("Nothing at this address", body, StringComparison.Ordinal);
        Assert.Contains("Not signed in", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Project_screens_do_not_render_their_content_to_an_anonymous_visitor()
    {
        // Authorization is enforced per component (AuthorizeRouteView plus
        // [Authorize]), not at the endpoint — an endpoint gate also blocks the
        // framework script and answers a browser with JSON. What matters is
        // that the screen body does not reach an anonymous reader.
        var client = _factory.CreateClient();

        var body = await client.GetStringAsync("/c/brewingcoder/p/tamp/build/179fe8b");

        Assert.Contains("not signed in", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Project hub", body, StringComparison.Ordinal);
    }

    // ------------------------------------------------------------------
    // URL builders
    // ------------------------------------------------------------------
    //
    // Every drill affordance in the design changes the URL. Hand-built strings
    // drift; these are the one place a route shape is written down.

    [Fact]
    public void Explorer_urls_carry_the_selection_and_the_line_anchor()
    {
        var url = Routes.Explorer("brewingcoder", "tamp", "179fe8b", Spines.Sast, "src/Api/Program.cs", 142);

        Assert.Equal("/c/brewingcoder/p/tamp/build/179fe8b/sast/src/Api/Program.cs#L142", url);
    }

    [Fact]
    public void Explorer_urls_omit_an_absent_selection_and_anchor()
    {
        var url = Routes.Explorer("brewingcoder", "tamp", "179fe8b", Spines.Dast);

        Assert.Equal("/c/brewingcoder/p/tamp/build/179fe8b/dast", url);
    }

    [Fact]
    public void Scope_segments_are_escaped_but_the_selection_keeps_its_slashes()
    {
        // A client name may contain characters that need escaping; a selection
        // is a path and must not have its separators mangled.
        var url = Routes.Explorer("Security Lab", "juice shop", "abc123", Spines.Sast, "app/routes/index.js");

        Assert.Contains("Security%20Lab", url, StringComparison.Ordinal);
        Assert.Contains("juice%20shop", url, StringComparison.Ordinal);
        Assert.EndsWith("/sast/app/routes/index.js", url, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Built_urls_resolve_against_the_real_route_table()
    {
        // Guards the seam between the builders and the @page directives: it is
        // possible to change one and not the other, and nothing else would
        // notice until a link broke in the browser.
        var client = _factory.CreateClient();
        string[] urls =
        [
            Routes.Portfolio,
            Routes.ProjectHub("brewingcoder", "tamp", "179fe8b"),
            Routes.Explorer("brewingcoder", "tamp", "179fe8b", Spines.Coverage, "src/Api/Program.cs"),
            Routes.Attestation("brewingcoder", "tamp", "179fe8b"),
            Routes.Poam("brewingcoder", "tamp"),
            Routes.PoamItem("brewingcoder", "tamp", "42"),
            Routes.Vex("brewingcoder", "tamp"),
            Routes.Policy("brewingcoder", "tamp"),
            Routes.Keys("brewingcoder", "tamp"),
            Routes.System(SystemPanels.Audit),
        ];

        // A plain loop, not Assert.All: an async lambda there is async void,
        // so a failed assertion inside it would never be observed and the
        // test would pass regardless.
        foreach (var url in urls)
        {
            var resp = await client.GetAsync(url);
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        }
    }

    [Fact]
    public void Portfolio_does_not_claim_the_root_while_the_spa_still_serves_it()
    {
        // An explicit Blazor route at "/" would shadow index.html. TFND-128
        // adds it at cutover; until then this is the guard.
        Assert.NotEqual("/", Routes.Portfolio);
    }
}
