namespace Tamp.Findings.Api.Tests;

// What the VEX screen renders when it cannot reach the database (TFND-99).
//
// An empty statement list reads as "no CVE has been explained away" — a claim
// about triage that this screen cannot make when it could not read anything.
public class VexRenderTests : IClassFixture<TestApiFactory>
{
    private readonly TestApiFactory _factory;

    public VexRenderTests(TestApiFactory factory) => _factory = factory;

    [Fact]
    public async Task The_screen_renders_rather_than_throwing()
    {
        var client = _factory.CreateSignedIn();

        var resp = await client.GetAsync("/c/BrewingCoder/p/tamp/vex");

        resp.EnsureSuccessStatusCode();
    }

    [Fact]
    public async Task An_unreachable_database_never_renders_as_an_empty_list()
    {
        var client = _factory.CreateSignedIn();

        var body = await client.GetStringAsync("/c/BrewingCoder/p/tamp/vex");

        Assert.Contains("Unavailable", body, StringComparison.Ordinal);
        Assert.DoesNotContain("No VEX statements on this project", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_deep_link_from_the_sbom_spine_renders_rather_than_throwing()
    {
        // The SBOM spine's VEX cell hands over the purl and advisory so the
        // author never has to find their own row again. A purl carries slashes,
        // a colon and an '@', so this is also the escaping check.
        var client = _factory.CreateSignedIn();

        var resp = await client.GetAsync(
            "/c/BrewingCoder/p/tamp/vex?purl=pkg%3Anuget%2FLog4Net%402.0.5&advisory=CVE-2021-44228");

        resp.EnsureSuccessStatusCode();
    }
}
