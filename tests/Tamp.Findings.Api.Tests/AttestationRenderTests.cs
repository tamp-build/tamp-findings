namespace Tamp.Findings.Api.Tests;

// What the attestation screen renders when it cannot reach the database
// (TFND-100).
//
// Someone signs this document. A half-populated attestation is worse than none,
// so the failure mode has to be a refusal to render, never a partial form.
public class AttestationRenderTests : IClassFixture<TestApiFactory>
{
    private readonly TestApiFactory _factory;

    public AttestationRenderTests(TestApiFactory factory) => _factory = factory;

    [Fact]
    public async Task The_screen_renders_rather_than_throwing()
    {
        var client = _factory.CreateSignedIn();

        var resp = await client.GetAsync("/c/BrewingCoder/p/tamp/build/179fe8b/attestation");

        resp.EnsureSuccessStatusCode();
    }

    [Fact]
    public async Task An_unreachable_database_renders_no_form_at_all()
    {
        var client = _factory.CreateSignedIn();

        var body = await client.GetStringAsync("/c/BrewingCoder/p/tamp/build/179fe8b/attestation");

        Assert.Contains("Unavailable", body, StringComparison.Ordinal);
        // Emphatically not a signature block over an empty practice list.
        Assert.DoesNotContain("SIGNATORY", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("tally__value", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_attestation_route_wins_over_the_explorer_spine_route()
    {
        // Both are five segments. "attestation" is a literal and {Spine} is a
        // parameter, so the literal wins — but only as long as nobody adds a
        // catch-all that outranks it.
        var client = _factory.CreateSignedIn();

        var body = await client.GetStringAsync("/c/BrewingCoder/p/tamp/build/179fe8b/attestation");

        Assert.Contains("Could not build the attestation", body, StringComparison.Ordinal);
        Assert.DoesNotContain("Unknown spine", body, StringComparison.Ordinal);
    }
}
