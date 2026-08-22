namespace Tamp.Findings.Api.Tests;

// The header (TFND-65). The URL chip is the visible proof that deep linking
// works — problem 1 on the brief's list was that nothing was addressable.
public class HeaderTests : IClassFixture<TestApiFactory>
{
    private readonly TestApiFactory _factory;

    public HeaderTests(TestApiFactory factory) => _factory = factory;

    [Fact]
    public async Task The_url_chip_shows_the_current_deep_link()
    {
        var client = _factory.CreateSignedIn();

        var body = await client.GetStringAsync("/c/brewingcoder/p/tamp/build/179fe8b/sast/src/Api/Program.cs");

        // The whole selection, slashes intact — a truncated or re-encoded path
        // would not be pasteable, which is the point of showing it.
        Assert.Contains("/c/brewingcoder/p/tamp/build/179fe8b/sast/src/Api/Program.cs", body, StringComparison.Ordinal);
        Assert.Contains("copy link", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_active_explorer_spine_takes_its_own_tab()
    {
        // So the reader can see which of the five they are in without opening
        // the sidebar.
        var client = _factory.CreateSignedIn();

        var body = await client.GetStringAsync("/c/brewingcoder/p/tamp/build/179fe8b/coverage");

        Assert.Contains("tab--active", body, StringComparison.Ordinal);
        Assert.Contains(">coverage<", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_system_tab_is_marked_as_instance_level()
    {
        var client = _factory.CreateSignedIn();

        var body = await client.GetStringAsync("/system/audit");

        // The strip marks System differently because it sits outside any
        // client or project scope.
        Assert.Contains("tab--system", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Project_tabs_are_absent_outside_a_project()
    {
        var client = _factory.CreateSignedIn();

        var body = await client.GetStringAsync("/portfolio");

        Assert.DoesNotContain(">Project hub<", body, StringComparison.Ordinal);
        Assert.DoesNotContain(">Attestation<", body, StringComparison.Ordinal);
        // Portfolio and System always survive.
        Assert.Contains(">Portfolio<", body, StringComparison.Ordinal);
        Assert.Contains(">System<", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_build_stamp_appears_only_when_a_build_is_in_scope()
    {
        var client = _factory.CreateSignedIn();

        var withBuild = await client.GetStringAsync("/c/brewingcoder/p/tamp/build/179fe8b");
        var withoutBuild = await client.GetStringAsync("/c/brewingcoder/p/tamp/poam");

        // "Canonical" is a real distinction — a non-canonical build does not
        // drive gates or attestation — so it must not appear where there is no
        // build at all.
        Assert.Contains("Canonical", withBuild, StringComparison.Ordinal);
        Assert.DoesNotContain("Canonical", withoutBuild, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_anonymous_visitor_is_offered_sign_in_rather_than_an_account_menu()
    {
        var client = _factory.CreateClient();

        var body = await client.GetStringAsync("/dev/primitives");

        Assert.Contains("Sign in", body, StringComparison.Ordinal);
        Assert.DoesNotContain("account__trigger", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_signed_in_visitor_gets_the_account_control_with_their_initials()
    {
        var client = _factory.CreateSignedIn(login: "scott.singleton");

        var body = await client.GetStringAsync("/portfolio");

        Assert.Contains("account__trigger", body, StringComparison.Ordinal);
        Assert.Contains("scott.singleton", body, StringComparison.Ordinal);
        // "scott.singleton" splits on the dot into two parts -> "SS".
        Assert.Contains(">SS<", body, StringComparison.Ordinal);
    }
}
