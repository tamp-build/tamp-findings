namespace Tamp.Findings.Api.Tests;

// What each explorer spine does when it cannot reach the database (TFND-90…94).
//
// This suite runs without Postgres, so every request here IS the
// database-down case. Two things are worth proving from it:
//
//  1. Every spine's queries actually resolve from DI. A missing registration
//     throws at @inject time, before OnParametersSetAsync ever runs, and shows
//     up here as a 500 rather than as the "Unavailable" card.
//  2. No spine ever renders an empty tree in place of an unreachable database.
//     A screen whose job is to report posture must never imply a clean one it
//     could not measure.
public class ExplorerSpineRenderTests : IClassFixture<TestApiFactory>
{
    private readonly TestApiFactory _factory;

    public ExplorerSpineRenderTests(TestApiFactory factory) => _factory = factory;

    public static TheoryData<string> Spines() =>
        new(Tamp.Findings.Web.Routing.Spines.All);

    [Theory]
    [MemberData(nameof(Spines))]
    public async Task A_spine_renders_rather_than_throwing(string spine)
    {
        var client = _factory.CreateSignedIn();

        var resp = await client.GetAsync($"/c/BrewingCoder/p/tamp/build/179fe8b/{spine}");

        resp.EnsureSuccessStatusCode();
    }

    [Theory]
    [MemberData(nameof(Spines))]
    public async Task An_unreachable_database_says_unavailable_on_every_spine(string spine)
    {
        var client = _factory.CreateSignedIn();

        var body = await client.GetStringAsync($"/c/BrewingCoder/p/tamp/build/179fe8b/{spine}");

        Assert.Contains("Unavailable", body, StringComparison.Ordinal);
        Assert.Contains("not clean", body, StringComparison.Ordinal);
        // "No open findings on this build" is the honest empty state for a
        // build that WAS measured. Showing it for a database nobody could
        // reach is the exact confusion this product exists to prevent.
        Assert.DoesNotContain("No open findings", body, StringComparison.Ordinal);
        Assert.DoesNotContain("No dependencies recorded", body, StringComparison.Ordinal);
        Assert.DoesNotContain("No coverage recorded", body, StringComparison.Ordinal);
        Assert.DoesNotContain("No test results recorded", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_unknown_spine_says_so_rather_than_rendering_an_empty_shell()
    {
        // A broken link, not an empty screen.
        var client = _factory.CreateSignedIn();

        var body = await client.GetStringAsync("/c/BrewingCoder/p/tamp/build/179fe8b/nonsense");

        Assert.Contains("Unknown spine", body, StringComparison.Ordinal);
    }
}
