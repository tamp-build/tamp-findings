using Tamp.Findings.Domain.Risk;

namespace Tamp.Findings.Application.Projects;

/// <summary>
/// The four-metric status summary of a build — Risk, Coverage, Tests, Ship gate — with each value's
/// band already resolved. ONE place computes it, so the project-hub header strip and the public badge
/// render the same numbers and the same colours and cannot drift. Carries raw values (not formatted
/// strings) so each surface can present them its own way (HTML spans vs. SVG text); what's shared is
/// the banding + the measured/unmeasured logic, which is exactly what must not diverge.
/// </summary>
public sealed record ProjectStatus(
    string ProjectName,
    string ClientName,
    string? Baseline,
    double RiskScore, string RiskBand,
    bool CoverageMeasured, double CoveragePercent, string CoverageBand,
    bool TestsMeasured, int TestsTotal, int TestsPassed, int TestsFailed, string TestsBand,
    bool ClearToShip, string ShipBand, IReadOnlyList<string> ShipReasons,
    string? CommitShaShort, DateTimeOffset BuiltAt)
{
    public static ProjectStatus From(ProjectHubData d)
    {
        // Coverage: banded off the project's own target/floor (higher-is-better); a missing report is
        // red, not a benign blank — the same "unmeasured is a failure" rule as the header.
        var coverageBand = d.Inputs.CoverageMeasured
            ? BandScale.Coverage(d.CoverageTarget, d.CoverageFloor).SlugFor(d.Inputs.SequenceCoveragePercent)
            : Band.Red.Slug();

        // Tests: green only when every test passes; banded on the pass rate when some fail; red when
        // nothing ran.
        var total = d.Inputs.TestsTotal;
        var failed = d.Inputs.TestsFailed;
        var passed = total - failed;
        var testsBand = !d.Inputs.TestsMeasured ? Band.Red.Slug()
            : failed == 0 ? Band.Green.Slug()
            : BandScale.Percent(100, 90, 75).SlugFor(total > 0 ? 100.0 * passed / total : 0);

        var reasons = d.Gates.ClearToShip
            ? []
            : d.Gates.Results.Where(r => r.Blocks)
                .Select(g => $"{GateEvaluator.Label(g.Key)} · {g.Observed}")
                .ToArray();

        var shortSha = d.CommitSha is { Length: > 7 } full ? full[..7] : d.CommitSha;

        return new ProjectStatus(
            d.Project.ProjectName, d.Project.ClientName, d.ComplianceBaseline,
            d.Risk.Score, d.Risk.Band,
            d.Inputs.CoverageMeasured, d.Inputs.SequenceCoveragePercent, coverageBand,
            d.Inputs.TestsMeasured, total, passed, failed, testsBand,
            d.Gates.ClearToShip, (d.Gates.ClearToShip ? Band.Green : Band.Red).Slug(), reasons,
            shortSha, d.BuiltAt);
    }
}
