namespace Tamp.Findings.Api.Tests;

// What the policy and gates editor renders when it cannot reach the database
// (TFND-104).
//
// Saving a policy moves every score on the instance, so the failure mode has to
// be no form at all rather than an editable one over guessed values.
public class PolicyRenderTests : IClassFixture<TestApiFactory>
{
    private readonly TestApiFactory _factory;

    public PolicyRenderTests(TestApiFactory factory) => _factory = factory;

    [Fact]
    public async Task The_screen_renders_rather_than_throwing()
    {
        var client = _factory.CreateSignedIn();

        var resp = await client.GetAsync("/c/BrewingCoder/p/tamp/settings/policy");

        resp.EnsureSuccessStatusCode();
    }

    [Fact]
    public async Task An_unreachable_database_renders_no_editable_form()
    {
        var client = _factory.CreateSignedIn();

        var body = await client.GetStringAsync("/c/BrewingCoder/p/tamp/settings/policy");

        Assert.Contains("Unavailable", body, StringComparison.Ordinal);
        // No weight inputs, and no Save button to press against nothing.
        Assert.DoesNotContain("input--num", body, StringComparison.Ordinal);
        Assert.DoesNotContain("Save policy", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_keys_tab_still_has_its_own_route()
    {
        // Policy moved out of the settings component into its own screen. This
        // is the check that the move did not take the sibling route with it.
        var client = _factory.CreateSignedIn();

        var resp = await client.GetAsync("/c/BrewingCoder/p/tamp/settings/keys");

        resp.EnsureSuccessStatusCode();
    }
}
