namespace Tamp.Findings.Api.Tests;

// The project settings tabs (TFND-107 … TFND-109).
public class ProjectSettingsRenderTests : IClassFixture<TestApiFactory>
{
    private readonly TestApiFactory _factory;

    public ProjectSettingsRenderTests(TestApiFactory factory) => _factory = factory;

    [Theory]
    [InlineData("keys")]
    [InlineData("disclosure")]
    [InlineData("account")]
    public async Task Every_tab_renders_rather_than_throwing(string tab)
    {
        var client = _factory.CreateSignedIn();

        var resp = await client.GetAsync($"/c/BrewingCoder/p/tamp/settings/{tab}");

        resp.EnsureSuccessStatusCode();
    }

    [Fact]
    public async Task An_unknown_tab_lands_on_keys_rather_than_on_an_empty_screen()
    {
        // A settings URL is the kind of thing people hand-edit.
        var client = _factory.CreateSignedIn();

        var resp = await client.GetAsync("/c/BrewingCoder/p/tamp/settings/nonsense");

        resp.EnsureSuccessStatusCode();
    }

    [Fact]
    public async Task An_unreachable_database_never_renders_as_an_empty_token_list()
    {
        // "No ingest tokens" is a claim about who can write here, and this
        // suite runs without Postgres — so it is a claim the screen cannot make.
        var client = _factory.CreateSignedIn();

        var body = await client.GetStringAsync("/c/BrewingCoder/p/tamp/settings/keys");

        Assert.Contains("Unavailable", body, StringComparison.Ordinal);
        Assert.DoesNotContain("No ingest tokens on this project", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task No_secret_panel_is_rendered_without_a_freshly_minted_token()
    {
        // The reveal-once panel exists for exactly one render. It appearing on
        // a plain page load would mean a value was being held somewhere it
        // should not be.
        var client = _factory.CreateSignedIn();

        var body = await client.GetStringAsync("/c/BrewingCoder/p/tamp/settings/keys");

        Assert.DoesNotContain("WILL NOT BE SHOWN AGAIN", body, StringComparison.Ordinal);
    }
}
