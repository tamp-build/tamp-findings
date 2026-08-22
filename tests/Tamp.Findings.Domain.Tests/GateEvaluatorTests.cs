using Tamp.Findings.Domain.Risk;

namespace Tamp.Findings.Domain.Tests;

// Gate evaluation had no coverage before TFND-38. These lock in the
// contract the SPA and the build evaluator both depend on: every
// well-known gate renders, disabled gates pass silently, and the new
// criticalDast gate reads DAST counts rather than SAST ones.
public class GateEvaluatorTests
{
    private static ProjectGatesConfig Gates(params (string Key, double? Threshold)[] enabled)
    {
        var cfg = new ProjectGatesConfig();
        foreach (var (key, threshold) in enabled)
            cfg.Gates[key] = new GateConfig { Enabled = true, Threshold = threshold };
        return cfg;
    }

    private static RiskInputs Clean() => new(
        0, 0, 0, 0, KevListedCves: 0,
        SecretsVerified: 0, SecretsUnverified: 0,
        SastCritical: 0, SastHigh: 0, SastMedium: 0, SastLow: 0,
        IacCritical: 0, IacHigh: 0,
        CoverageMeasured: true, SequenceCoveragePercent: 85,
        SbomComponents: 10, SbomOutdated: 0, SbomStale: 0,
        TestsMeasured: true, TestsTotal: 100, TestsFailed: 0,
        LicenseDenied: 0, LicenseStrongCopyleft: 0, LicenseUnknown: 0,
        RanSast: true, RanSecrets: true, RanIac: true, RanSbom: true, RanCoverage: true);

    private static GateResult Result(GateEvaluation e, string key) => e.Results.Single(r => r.Key == key);

    // ------------------------------------------------------------------
    // criticalDast
    // ------------------------------------------------------------------

    [Fact]
    public void Critical_dast_gate_fails_on_a_critical_dast_finding()
    {
        var inputs = Clean() with { DastCritical = 1 };
        var eval = GateEvaluator.Evaluate(Gates((GateKeys.CriticalDast, null)), inputs, 12, null, null);

        var gate = Result(eval, GateKeys.CriticalDast);
        Assert.True(gate.Enabled);
        Assert.False(gate.Passed);
        Assert.Contains("critical DAST", gate.Observed, StringComparison.Ordinal);
    }

    [Fact]
    public void Critical_dast_gate_reads_dast_counts_not_sast_counts()
    {
        // The two share a code shape, so a copy-paste slip here would make
        // the DAST gate silently mirror SAST. This is the test that catches it.
        var sastOnly = Clean() with { SastCritical = 5, DastCritical = 0 };
        var eval = GateEvaluator.Evaluate(Gates((GateKeys.CriticalDast, null)), sastOnly, 12, null, null);

        Assert.True(Result(eval, GateKeys.CriticalDast).Passed);
    }

    [Fact]
    public void Critical_sast_gate_is_unaffected_by_dast_findings()
    {
        var dastOnly = Clean() with { DastCritical = 5, SastCritical = 0 };
        var eval = GateEvaluator.Evaluate(Gates((GateKeys.CriticalSast, null)), dastOnly, 12, null, null);

        Assert.True(Result(eval, GateKeys.CriticalSast).Passed);
    }

    [Fact]
    public void Critical_dast_gate_honours_an_explicit_threshold()
    {
        var inputs = Clean() with { DastCritical = 2 };

        Assert.True(Result(GateEvaluator.Evaluate(Gates((GateKeys.CriticalDast, 2)), inputs, 1, null, null),
            GateKeys.CriticalDast).Passed);
        Assert.False(Result(GateEvaluator.Evaluate(Gates((GateKeys.CriticalDast, 1)), inputs, 1, null, null),
            GateKeys.CriticalDast).Passed);
    }

    [Fact]
    public void Critical_dast_gate_passes_when_disabled_even_with_findings()
    {
        var inputs = Clean() with { DastCritical = 99 };
        var eval = GateEvaluator.Evaluate(new ProjectGatesConfig(), inputs, 50, null, null);

        var gate = Result(eval, GateKeys.CriticalDast);
        Assert.False(gate.Enabled);
        Assert.True(gate.Passed);
        Assert.Equal(0, eval.Failed);
    }

    // ------------------------------------------------------------------
    // High gates — the reachable ones
    // ------------------------------------------------------------------

    [Fact]
    public void High_gates_fire_where_the_critical_gates_cannot()
    {
        // The situation that motivated these: SARIF's level vocabulary has no
        // "critical", so a scanner reporting through levels alone tops out at
        // High. ZAP found a confirmed SQL injection on a live target and it
        // arrived as High — criticalDast stayed green.
        var inputs = Clean() with { SastHigh = 3, DastHigh = 1 };

        var criticals = GateEvaluator.Evaluate(
            Gates((GateKeys.CriticalSast, null), (GateKeys.CriticalDast, null)), inputs, 20, null, null);
        Assert.True(Result(criticals, GateKeys.CriticalSast).Passed);
        Assert.True(Result(criticals, GateKeys.CriticalDast).Passed);

        var highs = GateEvaluator.Evaluate(
            Gates((GateKeys.HighSast, null), (GateKeys.HighDast, null)), inputs, 20, null, null);
        Assert.False(Result(highs, GateKeys.HighSast).Passed);
        Assert.False(Result(highs, GateKeys.HighDast).Passed);
    }

    [Fact]
    public void High_gates_read_their_own_severity_bucket()
    {
        // A copy-paste slip would have highSast reading Critical, which would
        // put it right back in the unreachable state it exists to escape.
        var criticalOnly = Clean() with { SastCritical = 9, DastCritical = 9, SastHigh = 0, DastHigh = 0 };
        var eval = GateEvaluator.Evaluate(
            Gates((GateKeys.HighSast, null), (GateKeys.HighDast, null)), criticalOnly, 40, null, null);

        Assert.True(Result(eval, GateKeys.HighSast).Passed);
        Assert.True(Result(eval, GateKeys.HighDast).Passed);
    }

    [Fact]
    public void High_gates_do_not_cross_wire_sast_and_dast()
    {
        var sastOnly = Clean() with { SastHigh = 4, DastHigh = 0 };
        var eval = GateEvaluator.Evaluate(
            Gates((GateKeys.HighSast, null), (GateKeys.HighDast, null)), sastOnly, 20, null, null);

        Assert.False(Result(eval, GateKeys.HighSast).Passed);
        Assert.True(Result(eval, GateKeys.HighDast).Passed);
    }

    [Fact]
    public void High_gates_honour_a_threshold()
    {
        // A team with existing High debt can hold the line at today's count
        // instead of being forced to disable the gate entirely.
        var inputs = Clean() with { SastHigh = 5 };

        Assert.True(Result(GateEvaluator.Evaluate(Gates((GateKeys.HighSast, 5)), inputs, 1, null, null),
            GateKeys.HighSast).Passed);
        Assert.False(Result(GateEvaluator.Evaluate(Gates((GateKeys.HighSast, 4)), inputs, 1, null, null),
            GateKeys.HighSast).Passed);
    }

    // ------------------------------------------------------------------
    // Shape guarantees the SPA relies on
    // ------------------------------------------------------------------

    [Fact]
    public void Every_well_known_gate_renders_even_when_unconfigured()
    {
        var eval = GateEvaluator.Evaluate(new ProjectGatesConfig(), Clean(), 5, null, null);

        foreach (var key in new[]
        {
            GateKeys.RiskScoreRegression, GateKeys.KevExposure, GateKeys.AnyCves,
            GateKeys.CriticalCves, GateKeys.HighCves, GateKeys.CriticalSast,
            GateKeys.HighSast, GateKeys.CriticalDast, GateKeys.HighDast,
            GateKeys.CriticalIac, GateKeys.VerifiedSecrets,
            GateKeys.DeniedLicenses, GateKeys.TestFailures, GateKeys.CoverageRegression,
            GateKeys.PoamPastDue,
        })
        {
            Assert.Single(eval.Results, r => r.Key == key);
        }
    }

    [Fact]
    public void Failed_and_passed_counts_ignore_disabled_gates()
    {
        var inputs = Clean() with { DastCritical = 1, SastCritical = 1 };
        var eval = GateEvaluator.Evaluate(
            Gates((GateKeys.CriticalDast, null), (GateKeys.CriticalSast, null)),
            inputs, 20, null, null);

        Assert.Equal(2, eval.Failed);
        Assert.Equal(0, eval.Passed);
    }
}
