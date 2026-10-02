using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Projects;
using Tamp.Findings.Application.Risk;
using Tamp.Findings.Domain.Values;
using Tamp.Findings.Web.Components.Primitives;
using Tamp.Findings.Web.Components.Project;

namespace Tamp.Findings.Integration.Tests;

[Collection(DatabaseCollection.Name)]
public class PageAQualityAndBannerTests
{
    private readonly DatabaseFixture _fx;
    public PageAQualityAndBannerTests(DatabaseFixture fx) => _fx = fx;

    private static QualityOverview Overview(bool failing, bool withCoverage, bool withGate, bool withFindings) => new(
        Ran: true,
        Findings: withFindings
            ?
            [
                new(Guid.NewGuid(), ScannerKind.OpenGrep, "S1", Severity.High, "A bug", null, "src/" + new string('x', 80) + ".cs", 12, null, "bug", FindingStatus.Open, DateTimeOffset.UtcNow),
                new(Guid.NewGuid(), ScannerKind.OpenGrep, "S2", Severity.Low, "A smell", null, null, null, null, null, FindingStatus.Fixed, DateTimeOffset.UtcNow),
            ]
            : [],
        Receipts:
        [
            new(ScannerKind.OpenGrep, "Succeeded", 2, DateTimeOffset.UtcNow, "sonar", "10.0", "analysis ok"),
            new(ScannerKind.Roslyn, "Failed", 0, null, "roslyn", null, null),
        ],
        Gate: withGate
            ? new QualityGateView(
                failing ? "ERROR" : "OK",
                failing
                    ? [new("coverage", "LT", "80", "61.2", true), new("bugs", "GT", "0", "0", false), new("custom", null, null, null, false)]
                    : [new("coverage", "LT", "80", "91.0", false)],
                [new("ncloc", "1200"), new("bugs", "0")], "sonarqube", "AX1", DateTimeOffset.UtcNow)
            : null,
        Coverage: withCoverage
            ? new AnalysisCoverageView(
                [new("C#", 40, 40, 5000, 100, "roslyn", null), new("TypeScript", 10, 30, 900, 33.3, null, "a.ts")],
                ["Python"], ["**/bin/**", "**/obj/**"], DateTimeOffset.UtcNow)
            : null,
        History:
        [
            new("abcdef0123456789", DateTimeOffset.UtcNow, 3, "ERROR", 1, 3),
            new("1234567", DateTimeOffset.UtcNow.AddDays(-1), 0, "OK", 0, 3),
            new(null, DateTimeOffset.UtcNow.AddDays(-2), 0, null, 0, 0),
        ]);

    [SkippableFact]
    public async Task Quality_panel_renders_gate_findings_coverage_receipts_and_history()
    {
        Skip.IfNot(_fx.Available);
        var w = await PageAWorld.SeedAsync(_fx);

        async Task<PageARenderer> Open(QualityOverview? o)
        {
            var h = await PageAHost.ForAsync(_fx, w.Admin, "/");
            return await h.OpenAsync<QualityPanel>(("Overview", o));
        }

        var failing = await Open(Overview(failing: true, withCoverage: true, withGate: true, withFindings: true));
        failing.Expect("Quality gate ERROR");
        failing.Expect("condition failed");
        failing.Expect("FAILED");
        failing.Expect("Languages with source but no analyzer");
        failing.Expect("Excludes");
        failing.Expect("Scan provenance");
        failing.Expect("no verdict");
        failing.Expect("1/3 failed");
        failing.Expect("2 issues");

        var passing = await Open(Overview(failing: false, withCoverage: false, withGate: true, withFindings: false));
        passing.Expect("Quality gate OK");
        passing.Expect("All 1 conditions passed");
        passing.Expect("completeness of the analysis is unproven");
        passing.Expect("No bugs or code smells");

        (await Open(Overview(failing: false, withCoverage: false, withGate: false, withFindings: false))).Expect("No gate verdict");
        (await Open(null)).Expect("No code-quality analysis");
        (await Open(QualityOverview.Empty)).Expect("No code-quality analysis");
    }

    [SkippableFact]
    public async Task New_build_banner_appears_when_the_project_publishes_and_refreshes_on_click()
    {
        Skip.IfNot(_fx.Available);
        var w = await PageAWorld.SeedAsync(_fx);
        await using var h = await PageAHost.ForAsync(_fx, w.Admin, "/c/x/p/y/build/abc");
        var banner = await h.OpenAsync<NewBuildBanner>(("ProjectId", (Guid?)w.Project.Id));
        Assert.DoesNotContain("newer build", banner.Text);

        h.Services.GetRequiredService<BuildUpdateNotifier>().Publish(w.Project.Id);
        await Task.Delay(2500);
        banner.Expect("A newer build has been ingested");
        await banner.ClickAsync("Refresh");
        Assert.NotNull(banner.LastNavigation);

        // No project resolved: nothing subscribed, nothing shown.
        await using var h2 = await PageAHost.ForAsync(_fx, w.Admin, "/");
        var none = await h2.OpenAsync<NewBuildBanner>(("ProjectId", (Guid?)null));
        Assert.DoesNotContain("newer build", none.Text);
    }
}
