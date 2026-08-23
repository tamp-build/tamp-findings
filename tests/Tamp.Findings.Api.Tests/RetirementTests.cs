namespace Tamp.Findings.Api.Tests;

// The cutover (TFND-127 / TFND-128).
//
// The acceptance criteria are "no route 404s that previously worked" and "the
// deployed instance runs Blazor only". These are the checks that hold both.
public class RetirementTests : IClassFixture<TestApiFactory>
{
    private readonly TestApiFactory _factory;

    public RetirementTests(TestApiFactory factory) => _factory = factory;

    [Fact]
    public async Task The_root_is_the_portfolio_rather_than_a_javascript_bundle()
    {
        var client = _factory.CreateSignedIn();

        var body = await client.GetStringAsync("/");

        // Blazor's own markup, not index.html.
        Assert.Contains("blazor.web.js", body, StringComparison.Ordinal);
        Assert.DoesNotContain("<div id=\"root\">", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_old_portfolio_route_still_answers()
    {
        // It is in links, bookmarks and this repo's own docs. Breaking it to
        // save a line would be a gratuitous 404.
        var client = _factory.CreateSignedIn();

        var resp = await client.GetAsync("/portfolio");

        resp.EnsureSuccessStatusCode();
    }

    [Fact]
    public async Task An_unmatched_url_says_so_instead_of_silently_serving_the_shell()
    {
        // With MapFallbackToFile gone, a typo reaches Blazor's NotFound. It
        // used to be answered with index.html, which made a mistyped address
        // look like a working page that failed to load.
        var client = _factory.CreateSignedIn();

        var body = await client.GetStringAsync("/this-route-does-not-exist");

        Assert.Contains("Nothing at this address", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_not_found_page_keeps_the_readers_navigation()
    {
        // A bare 404 strands someone whose bookmark went stale — the most
        // common cause of landing here, and someone who still has somewhere to
        // go.
        var client = _factory.CreateSignedIn();

        var body = await client.GetStringAsync("/this-route-does-not-exist");

        Assert.Contains("Back to the portfolio", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_client_tier_is_navigable()
    {
        // "The client tier of the load-bearing hierarchy is navigable, not a
        // gap between Portfolio and Project."
        var client = _factory.CreateSignedIn();

        var resp = await client.GetAsync("/c/BrewingCoder");

        resp.EnsureSuccessStatusCode();
    }

    [Fact]
    public async Task An_unreachable_database_never_renders_the_client_as_empty()
    {
        // This suite runs without Postgres, so every client request here IS the
        // database-down case. "No projects under this client" is a claim about
        // what an organisation ships, and it must not be made by accident.
        var client = _factory.CreateSignedIn();

        var body = await client.GetStringAsync("/c/BrewingCoder");

        Assert.Contains("Unavailable", body, StringComparison.Ordinal);
        Assert.DoesNotContain("No projects under this client", body, StringComparison.Ordinal);
    }
}
