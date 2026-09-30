using Tamp.Findings.Application.Projects;
using Tamp.Findings.Domain.Risk;
using Xunit;

namespace Tamp.Findings.Application.Tests;

// The public status badge SVG (Project.BadgeKey). Colours come from the shared Band hex, values from
// the shared ProjectStatus, and the build stamp is drawn so a proxy-cached copy reads as stale.
public class BadgeSvgTests
{
    private static ProjectStatus Status(
        bool clear = false, IReadOnlyList<string>? reasons = null,
        bool coverageMeasured = true, bool testsMeasured = true, int failed = 0) =>
        new(
            "tamp-core", "Tamp", "FedRAMP High",
            RiskScore: 0.1, RiskBand: "green",
            CoverageMeasured: coverageMeasured, CoveragePercent: 83.5, CoverageBand: "green",
            TestsMeasured: testsMeasured, TestsTotal: 1405, TestsPassed: 1405 - failed, TestsFailed: failed, TestsBand: failed == 0 ? "green" : "orange",
            ClearToShip: clear, ShipBand: clear ? "green" : "red",
            ShipReasons: reasons ?? (clear ? [] : ["Control coverage · 11 of 370 controls unmapped"]),
            CommitShaShort: "1e67ef8", BuiltAt: new DateTimeOffset(2026, 9, 29, 22, 31, 0, TimeSpan.Zero));

    [Fact]
    public void Renders_valid_svg_with_values_bands_and_build_stamp()
    {
        var svg = BadgeSvg.Render(Status(), new DateTimeOffset(2026, 9, 30, 1, 0, 0, TimeSpan.Zero));
        Assert.StartsWith("<svg", svg);
        Assert.EndsWith("</svg>", svg);
        Assert.Contains("tamp-core", svg);
        Assert.Contains("Tamp · FedRAMP High", svg);
        Assert.Contains("83.5%", svg);
        Assert.Contains("1,405 / 1,405", svg);
        Assert.Contains("✕ Blocked", svg);
        Assert.Contains(Band.Green.Hex(), svg);   // green cells
        Assert.Contains(Band.Red.Hex(), svg);      // blocked ship
        // Staleness stamp: sha + built time on the card.
        Assert.Contains("1e67ef8", svg);
        Assert.Contains("2026-09-29 22:31 UTC", svg);
        // Wrapped ship reason present.
        Assert.Contains("Control coverage", svg);
    }

    [Fact]
    public void Clear_build_shows_no_ship_reasons()
    {
        var svg = BadgeSvg.Render(Status(clear: true), DateTimeOffset.UtcNow);
        Assert.Contains("✓ Clear", svg);
        Assert.DoesNotContain("Blocked", svg);
    }

    [Fact]
    public void Unmeasured_coverage_and_tests_read_as_no_data()
    {
        var svg = BadgeSvg.Render(Status(coverageMeasured: false, testsMeasured: false), DateTimeOffset.UtcNow);
        Assert.Contains("no data", svg);
    }

    [Fact]
    public void Multiple_blocking_gates_collapse_to_a_count()
    {
        var svg = BadgeSvg.Render(Status(reasons: ["Control coverage · x", "Test failures · 3 failed"]), DateTimeOffset.UtcNow);
        Assert.Contains("2 gates blocking", svg);
    }

    [Fact]
    public void Escapes_xml_in_the_project_name()
    {
        var s = Status() with { ProjectName = "a<b>&\"c" };
        var svg = BadgeSvg.Render(s, DateTimeOffset.UtcNow);
        Assert.Contains("a&lt;b&gt;&amp;&quot;c", svg);
        Assert.DoesNotContain("<b>", svg);
    }

    [Fact]
    public void Unbuilt_badge_says_so()
    {
        var svg = BadgeSvg.RenderUnbuilt("tamp-core", "Tamp · FedRAMP High");
        Assert.Contains("no build ingested yet", svg);
        Assert.Contains("tamp-core", svg);
    }
}
