namespace Tamp.Findings.Api.Tests;

// The accessibility spine (TFND-27).
//
// Any UI-facing federal software must conform to Section 508 (29 U.S.C. § 794d)
// and WCAG 2.1 AA. Before this, accessibility defects did not surface in the
// product at all — a silent gap that blocks federal acceptance as surely as an
// unpatched CVE does.
public class AccessibilitySpineTests : IClassFixture<TestApiFactory>
{
    private readonly TestApiFactory _factory;

    public AccessibilitySpineTests(TestApiFactory factory) => _factory = factory;

    [Fact]
    public async Task The_spine_has_its_own_route()
    {
        var client = _factory.CreateSignedIn();

        var resp = await client.GetAsync("/c/BrewingCoder/p/tamp/build/179fe8b/a11y");

        resp.EnsureSuccessStatusCode();
    }

    [Fact]
    public async Task It_is_not_an_unknown_spine()
    {
        // It is a sixth spine, not a filter on DAST: an accessibility defect is
        // read by UX and compliance, and burying it among security alerts would
        // put it in front of the wrong people.
        var client = _factory.CreateSignedIn();

        var body = await client.GetStringAsync("/c/BrewingCoder/p/tamp/build/179fe8b/a11y");

        Assert.DoesNotContain("Unknown spine", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task It_appears_in_the_spine_strip()
    {
        var client = _factory.CreateSignedIn();

        var body = await client.GetStringAsync("/c/BrewingCoder/p/tamp/build/179fe8b/sast");

        Assert.Contains("/a11y", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_unreachable_database_never_claims_a_conformant_interface()
    {
        // "No open accessibility findings" is a claim about Section 508
        // conformance, and this suite runs without Postgres.
        var client = _factory.CreateSignedIn();

        var body = await client.GetStringAsync("/c/BrewingCoder/p/tamp/build/179fe8b/a11y");

        Assert.Contains("Unavailable", body, StringComparison.Ordinal);
        Assert.DoesNotContain("No open accessibility findings", body, StringComparison.Ordinal);
    }
}
