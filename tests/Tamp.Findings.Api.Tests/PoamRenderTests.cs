namespace Tamp.Findings.Api.Tests;

// What the POA&M screen renders when it cannot reach the database (TFND-95).
//
// Same principle as the project hub and the explorer spines: this suite runs
// without Postgres, so every request here IS the database-down case. An empty
// POA&M table reads as "nothing outstanding", which is the single most
// dangerous thing this screen could say when it does not actually know.
public class PoamRenderTests : IClassFixture<TestApiFactory>
{
    private readonly TestApiFactory _factory;

    public PoamRenderTests(TestApiFactory factory) => _factory = factory;

    [Fact]
    public async Task The_screen_renders_rather_than_throwing()
    {
        var client = _factory.CreateSignedIn();

        var resp = await client.GetAsync("/c/BrewingCoder/p/tamp/poam");

        resp.EnsureSuccessStatusCode();
    }

    [Fact]
    public async Task An_unreachable_database_never_renders_as_an_empty_plan()
    {
        var client = _factory.CreateSignedIn();

        var body = await client.GetStringAsync("/c/BrewingCoder/p/tamp/poam");

        Assert.Contains("Unavailable", body, StringComparison.Ordinal);
        Assert.DoesNotContain("No POA&amp;M items on this project", body, StringComparison.Ordinal);
        // And emphatically not a green-looking stats strip full of zeroes.
        Assert.DoesNotContain("stat__value", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_deep_linked_item_renders_rather_than_throwing()
    {
        // A stale link — a deleted item, a URL pasted from another deployment.
        var client = _factory.CreateSignedIn();

        var resp = await client.GetAsync(
            $"/c/BrewingCoder/p/tamp/poam/{Guid.NewGuid()}");

        resp.EnsureSuccessStatusCode();
    }

    [Fact]
    public async Task A_malformed_item_id_does_not_throw()
    {
        var client = _factory.CreateSignedIn();

        var resp = await client.GetAsync("/c/BrewingCoder/p/tamp/poam/not-a-guid");

        resp.EnsureSuccessStatusCode();
    }
}
