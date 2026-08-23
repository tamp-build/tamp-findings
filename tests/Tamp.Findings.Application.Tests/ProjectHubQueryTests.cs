using Tamp.Findings.Application.Projects;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Risk;

namespace Tamp.Findings.Application.Tests;

// The project hub's shape (TFND-77 / TFND-78 / TFND-79).
//
// These assert the CONTRACT the hub renders against, not the database access —
// the query needs Postgres and the suite runs without one. What matters here is
// that the hub is handed domain types rather than DTOs, because the score, its
// breakdown and the gate verdicts have to agree on screen and every flattening
// step is somewhere they could stop agreeing.
public class ProjectHubQueryTests
{
    [Fact]
    public void The_hub_carries_domain_types_not_flattened_dtos()
    {
        // The "9 gates enabled" line that contradicted a computed 10 was a
        // DTO-drift bug, and "sharing the domain types directly with the UI"
        // is the hand-off's stated reason the port is worth doing.
        var risk = typeof(ProjectHubData).GetProperty(nameof(ProjectHubData.Risk))!;
        var gates = typeof(ProjectHubData).GetProperty(nameof(ProjectHubData.Gates))!;

        Assert.Equal(typeof(RiskResult), risk.PropertyType);
        Assert.Equal(typeof(GateEvaluation), gates.PropertyType);
    }

    [Fact]
    public void Gates_hang_off_the_project_not_the_policy()
    {
        // A policy defines HOW to score; the project decides what blocks a
        // release with it. Two projects can share Tamp Standard v1 and gate
        // differently, so reading gates off the policy would silently couple
        // them.
        var gatesOnProject = typeof(Project).GetProperty(nameof(Project.GatesConfig));
        var gatesOnPolicy = typeof(RiskPolicy).GetProperty("Gates");

        Assert.NotNull(gatesOnProject);
        Assert.Null(gatesOnPolicy);
    }

    [Fact]
    public void An_unconfigured_project_has_no_enabled_gates_rather_than_all_passing()
    {
        // Renders as "clear to ship, 0 gates enabled" — honest, and visibly
        // different from "all gates passing", which would imply checks ran.
        var evaluation = GateEvaluator.Evaluate(
            new ProjectGatesConfig(), CleanInputs(), currentScore: 90, prior: null, priorScore: null);

        Assert.Equal(0, evaluation.Enabled);
        Assert.Equal(0, evaluation.Blocking);
        Assert.True(evaluation.ClearToShip);
    }

    [Fact]
    public void An_unscanned_project_blocks_and_reports_unknowns_not_passes()
    {
        // What the hub's gate rail must render, and the reason it needed a
        // third verdict state at all: without it the rail would read PASS
        // directly above scan receipts saying the scanner never ran.
        var config = new ProjectGatesConfig();
        foreach (var key in new[] { "criticalSast", "highSast", "criticalDast" })
            config.Gates[key] = new GateConfig { Enabled = true };

        var evaluation = Evaluate(NeverScanned(), currentScore: 0, config: config);

        Assert.Equal(3, evaluation.Enabled);
        Assert.Equal(0, evaluation.Passed);
        Assert.Equal(3, evaluation.Unknown);
        Assert.False(evaluation.ClearToShip);
    }

    [Fact]
    public void Every_scored_category_appears_in_the_breakdown_including_zeros()
    {
        // The old rings drew six of twelve. Showing all of them is the point:
        // a category contributing nothing is information, and a disabled one
        // is different information again.
        var policy = RiskPolicyDefaults.BuildTampStandardV1();

        var result = RiskScorer.Compute(policy, CleanInputs());

        Assert.Equal(policy.Categories.Count, result.Breakdown.Count);
        Assert.Contains(result.Breakdown, r => r.Contribution == 0);
    }

    private static RiskInputs CleanInputs() => new(
        0, 0, 0, 0, KevListedCves: 0,
        SecretsVerified: 0, SecretsUnverified: 0,
        SastCritical: 0, SastHigh: 0, SastMedium: 0, SastLow: 0,
        IacCritical: 0, IacHigh: 0,
        CoverageMeasured: true, SequenceCoveragePercent: 85,
        SbomComponents: 10, SbomOutdated: 0, SbomStale: 0,
        TestsMeasured: true, TestsTotal: 100, TestsFailed: 0,
        LicenseDenied: 0, LicenseStrongCopyleft: 0, LicenseUnknown: 0,
        RanSast: true, RanSecrets: true, RanIac: true, RanSbom: true, RanCoverage: true,
        RanDast: true);

    private static GateEvaluation Evaluate(RiskInputs inputs, double currentScore, ProjectGatesConfig config) =>
        GateEvaluator.Evaluate(config, inputs, currentScore, prior: null, priorScore: null);

    private static RiskInputs NeverScanned() => CleanInputs() with
    {
        CoverageMeasured = false, TestsMeasured = false, SbomComponents = 0,
        RanSast = false, RanSecrets = false, RanIac = false,
        RanSbom = false, RanCoverage = false, RanDast = false,
    };
}
