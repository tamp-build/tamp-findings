namespace Tamp.Findings.Api.Tests;

// The by-rule grouping toggle (TFND-18).
public class RuleGroupingRenderTests : IClassFixture<TestApiFactory>
{
    private readonly TestApiFactory _factory;

    public RuleGroupingRenderTests(TestApiFactory factory) => _factory = factory;

    [Theory]
    [InlineData("sast")]
    [InlineData("dast")]
    public async Task The_grouping_toggle_is_offered_on_the_finding_spines(string spine)
    {
        // It has to be in the URL, not a stored preference: a link to a rule
        // breakdown is a link somebody sends.
        var client = _factory.CreateSignedIn();

        var body = await client.GetStringAsync($"/c/BrewingCoder/p/tamp/build/179fe8b/{spine}");

        Assert.Contains("Group by", body, StringComparison.Ordinal);
        Assert.Contains("?group=rule", body, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("sbom")]
    [InlineData("coverage")]
    [InlineData("tests")]
    public async Task Spines_with_no_rules_do_not_offer_the_toggle(string spine)
    {
        // A control that does nothing is worse than an absent one — it teaches
        // the reader the screen is unreliable.
        var client = _factory.CreateSignedIn();

        var body = await client.GetStringAsync($"/c/BrewingCoder/p/tamp/build/179fe8b/{spine}");

        Assert.DoesNotContain("Group by", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Grouping_by_rule_renders_rather_than_throwing()
    {
        var client = _factory.CreateSignedIn();

        var resp = await client.GetAsync("/c/BrewingCoder/p/tamp/build/179fe8b/sast?group=rule");

        resp.EnsureSuccessStatusCode();
    }

    [Fact]
    public async Task An_unknown_grouping_falls_back_to_path_rather_than_an_empty_tree()
    {
        // A query parameter is the kind of thing people hand-edit.
        var client = _factory.CreateSignedIn();

        var resp = await client.GetAsync("/c/BrewingCoder/p/tamp/build/179fe8b/sast?group=nonsense");

        resp.EnsureSuccessStatusCode();
    }
}
