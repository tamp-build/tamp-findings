namespace Tamp.Findings.Api.Tests;

// What the project hub renders when it has no data to render (TFND-77).
//
// The API suite runs without Postgres, so the populated hub cannot be asserted
// here — that needs an integration test against a real database. What CAN be
// asserted is the state that matters most and is easiest to get wrong: a
// project that has never been scanned.
public class ProjectHubRenderTests : IClassFixture<TestApiFactory>
{
    private readonly TestApiFactory _factory;

    public ProjectHubRenderTests(TestApiFactory factory) => _factory = factory;

    [Fact]
    public async Task The_hub_does_not_error_when_the_project_cannot_be_resolved()
    {
        // A stale deep link — a renamed project, a pasted URL from a different
        // deployment — must land somewhere legible rather than throwing.
        var client = _factory.CreateSignedIn();

        var resp = await client.GetAsync("/c/nobody/p/nothing/build/deadbeef");

        resp.EnsureSuccessStatusCode();
    }

    [Fact]
    public async Task A_project_with_no_build_never_renders_as_a_zero_score()
    {
        // The failure mode this guards: rendering 0.0 for a project nobody has
        // scanned. Zero implies something was measured and came back bad. "A
        // project with a green score and no recent scan is not healthy" — and
        // a red score it never earned is worse.
        var client = _factory.CreateSignedIn();

        var body = await client.GetStringAsync("/c/nobody/p/nothing/build/deadbeef");

        Assert.DoesNotContain("score__value", body, StringComparison.Ordinal);
    }
}
