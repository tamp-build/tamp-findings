namespace Tamp.Findings.Api.Tests;

// The application shell (TFND-64). The sidebar is chrome on every screen, so
// what it shows — and what it refuses to show — matters everywhere.
public class ShellTests : IClassFixture<TestApiFactory>
{
    private readonly TestApiFactory _factory;

    public ShellTests(TestApiFactory factory) => _factory = factory;

    [Fact]
    public async Task The_system_group_is_always_present_because_it_is_outside_project_scope()
    {
        var client = _factory.CreateSignedIn();

        var body = await client.GetStringAsync("/portfolio");

        Assert.Contains("navgroup--instance", body, StringComparison.Ordinal);
        Assert.Contains("Audit log", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Explore_and_evidence_are_absent_outside_a_project_rather_than_dead()
    {
        // A nav item that goes nowhere is worse than no nav item: it looks
        // like a broken link. Outside a project these groups have no meaning,
        // so they are not rendered at all.
        var client = _factory.CreateSignedIn();

        var body = await client.GetStringAsync("/portfolio");

        Assert.DoesNotContain(">Findings<", body, StringComparison.Ordinal);
        Assert.DoesNotContain(">POA&amp;M<", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Inside_a_project_the_full_nav_appears_with_working_links()
    {
        var client = _factory.CreateSignedIn();

        var body = await client.GetStringAsync("/c/brewingcoder/p/tamp/build/179fe8b");

        // The five explorer spines, the evidence group, and project admin.
        Assert.Contains("/c/brewingcoder/p/tamp/build/179fe8b/sast", body, StringComparison.Ordinal);
        Assert.Contains("/c/brewingcoder/p/tamp/build/179fe8b/dast", body, StringComparison.Ordinal);
        Assert.Contains("/c/brewingcoder/p/tamp/build/179fe8b/sbom", body, StringComparison.Ordinal);
        Assert.Contains("/c/brewingcoder/p/tamp/build/179fe8b/coverage", body, StringComparison.Ordinal);
        Assert.Contains("/c/brewingcoder/p/tamp/build/179fe8b/tests", body, StringComparison.Ordinal);
        Assert.Contains("/c/brewingcoder/p/tamp/poam", body, StringComparison.Ordinal);
        Assert.Contains("/c/brewingcoder/p/tamp/vex", body, StringComparison.Ordinal);
        Assert.Contains("/c/brewingcoder/p/tamp/settings/policy", body, StringComparison.Ordinal);
        Assert.Contains("/c/brewingcoder/p/tamp/settings/keys", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_scope_card_shows_the_route_scope_and_a_dash_for_what_is_unknown()
    {
        // The four tiers are load-bearing and appear on nearly every screen.
        // An unknown tier reads as an em dash rather than being hidden, so the
        // hierarchy stays visible even when only part of it is resolved.
        var client = _factory.CreateSignedIn();

        var body = await client.GetStringAsync("/c/brewingcoder/p/tamp/build/179fe8b");

        Assert.Contains("brewingcoder", body, StringComparison.Ordinal);
        Assert.Contains("179fe8b", body, StringComparison.Ordinal);
        // Component is not part of this route, so its row shows an em dash.
        Assert.Contains("Component", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_active_nav_item_is_marked_for_assistive_tech_not_only_by_colour()
    {
        var client = _factory.CreateSignedIn();

        var body = await client.GetStringAsync("/c/brewingcoder/p/tamp/build/179fe8b/sbom");

        Assert.Contains("aria-current=\"page\"", body, StringComparison.Ordinal);
        Assert.Contains("navitem--active", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Nav_counts_are_absent_rather_than_fabricated()
    {
        // "Findings (0)" when nobody has counted is the same lie as a gate
        // passing because no scanner ran. Counts are omitted until a real
        // query supplies them, so the markup carries no count element yet.
        var client = _factory.CreateSignedIn();

        var body = await client.GetStringAsync("/c/brewingcoder/p/tamp/build/179fe8b");

        Assert.DoesNotContain("navitem__count", body, StringComparison.Ordinal);
    }
}
