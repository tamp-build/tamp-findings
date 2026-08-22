namespace Tamp.Findings.Api.Tests;

// View preferences (TFND-66). Density and deltas are persona settings, not
// screen settings — the brief called serving four personas from one density
// "the central design problem".
public class ViewPreferenceTests : IClassFixture<TestApiFactory>
{
    private readonly TestApiFactory _factory;

    public ViewPreferenceTests(TestApiFactory factory) => _factory = factory;

    [Fact]
    public async Task Density_defaults_to_comfortable()
    {
        var client = _factory.CreateSignedIn();

        var body = await client.GetStringAsync("/portfolio");

        Assert.Contains(">comfortable<", body, StringComparison.Ordinal);
        Assert.DoesNotContain("density-compact", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Deltas_default_on_because_the_old_ui_was_not_time_aware()
    {
        // The brief's ninth problem was that nothing was time-aware. A build
        // score with no comparison is the state the redesign set out to fix,
        // so opting OUT is the deliberate act, not opting in.
        var client = _factory.CreateSignedIn();

        var body = await client.GetStringAsync("/c/brewingcoder/p/tamp/build/179fe8b");

        Assert.Contains("deltas on", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_delta_toggle_is_absent_without_a_build_to_compare()
    {
        // Absent rather than inert: a control that cannot do anything is worse
        // than no control, because it reads as broken.
        var client = _factory.CreateSignedIn();

        var body = await client.GetStringAsync("/portfolio");

        Assert.DoesNotContain("deltas on", body, StringComparison.Ordinal);
        Assert.DoesNotContain("deltas off", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_density_control_is_always_available()
    {
        // Unlike deltas, density means something on every screen with a table.
        var client = _factory.CreateSignedIn();

        var portfolio = await client.GetStringAsync("/portfolio");
        var hub = await client.GetStringAsync("/c/brewingcoder/p/tamp/build/179fe8b");

        Assert.Contains("Row density", portfolio, StringComparison.Ordinal);
        Assert.Contains("Row density", hub, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Prerender_does_not_fail_when_local_storage_is_unavailable()
    {
        // localStorage throws outright in a private window or with site data
        // blocked, and there is no browser at all during prerender. A lost
        // preference is a convenience not working; a thrown one would break
        // the render, so every access is guarded.
        var client = _factory.CreateSignedIn();

        var resp = await client.GetAsync("/portfolio");

        resp.EnsureSuccessStatusCode();
    }
}
