namespace Tamp.Findings.Api.Tests;

// The five instance panels (TFND-110 … TFND-114).
public class SystemAdminRenderTests : IClassFixture<TestApiFactory>
{
    private readonly TestApiFactory _factory;

    public SystemAdminRenderTests(TestApiFactory factory) => _factory = factory;

    public static TheoryData<string> Panels() =>
        new(Tamp.Findings.Web.Routing.SystemPanels.All);

    [Theory]
    [MemberData(nameof(Panels))]
    public async Task Every_panel_renders_rather_than_throwing(string panel)
    {
        var client = _factory.CreateSignedIn();

        var resp = await client.GetAsync($"/system/{panel}");

        resp.EnsureSuccessStatusCode();
    }

    [Fact]
    public async Task An_unknown_panel_says_so_rather_than_rendering_an_empty_shell()
    {
        var client = _factory.CreateSignedIn();

        var body = await client.GetStringAsync("/system/nonsense");

        Assert.Contains("Unknown panel", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_unreachable_database_never_renders_as_an_empty_user_list()
    {
        // "No users yet" is a claim about who has access to this deployment,
        // and this suite runs without Postgres.
        var client = _factory.CreateSignedIn();

        var body = await client.GetStringAsync("/system/users");

        Assert.Contains("Unavailable", body, StringComparison.Ordinal);
        Assert.DoesNotContain("No users yet", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Every_panel_states_that_changes_are_instance_wide()
    {
        // The panels sit outside any client or project scope, and somebody
        // arriving from a project screen needs to know the blast radius changed.
        var client = _factory.CreateSignedIn();

        var body = await client.GetStringAsync("/system/settings");

        Assert.Contains("every tenant on this deployment", body, StringComparison.Ordinal);
    }
}
