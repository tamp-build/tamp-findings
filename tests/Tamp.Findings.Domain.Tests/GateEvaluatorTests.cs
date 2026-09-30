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
        RanSast: true, RanSecrets: true, RanIac: true, RanSbom: true, RanCoverage: true, RanSca: true,
        // Clean() means EVERY expected scanner ran and found nothing. Without
        // this the DAST gates would be Unknown rather than Pass, and a test
        // that sets DastCritical while RanDast is false describes a build
        // that cannot exist (TFND-74).
        RanDast: true);

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
        Assert.Equal(GateVerdict.Fail, gate.Verdict);
        Assert.Contains("critical DAST", gate.Observed, StringComparison.Ordinal);
    }

    [Fact]
    public void Critical_dast_gate_reads_dast_counts_not_sast_counts()
    {
        // The two share a code shape, so a copy-paste slip here would make
        // the DAST gate silently mirror SAST. This is the test that catches it.
        var sastOnly = Clean() with { SastCritical = 5, DastCritical = 0 };
        var eval = GateEvaluator.Evaluate(Gates((GateKeys.CriticalDast, null)), sastOnly, 12, null, null);

        Assert.Equal(GateVerdict.Pass, Result(eval, GateKeys.CriticalDast).Verdict);
    }

    [Fact]
    public void Critical_sast_gate_is_unaffected_by_dast_findings()
    {
        var dastOnly = Clean() with { DastCritical = 5, SastCritical = 0 };
        var eval = GateEvaluator.Evaluate(Gates((GateKeys.CriticalSast, null)), dastOnly, 12, null, null);

        Assert.Equal(GateVerdict.Pass, Result(eval, GateKeys.CriticalSast).Verdict);
    }

    [Fact]
    public void Critical_dast_gate_honours_an_explicit_threshold()
    {
        var inputs = Clean() with { DastCritical = 2 };

        Assert.Equal(GateVerdict.Pass, Result(GateEvaluator.Evaluate(Gates((GateKeys.CriticalDast, 2)), inputs, 1, null, null),
            GateKeys.CriticalDast).Verdict);
        Assert.Equal(GateVerdict.Fail, Result(GateEvaluator.Evaluate(Gates((GateKeys.CriticalDast, 1)), inputs, 1, null, null),
            GateKeys.CriticalDast).Verdict);
    }

    [Fact]
    public void Critical_dast_gate_passes_when_disabled_even_with_findings()
    {
        var inputs = Clean() with { DastCritical = 99 };
        var eval = GateEvaluator.Evaluate(new ProjectGatesConfig(), inputs, 50, null, null);

        var gate = Result(eval, GateKeys.CriticalDast);
        Assert.False(gate.Enabled);
        Assert.False(gate.Blocks);
        Assert.Equal(0, eval.Failed);
        Assert.Equal(0, eval.Blocking);
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
        Assert.Equal(GateVerdict.Pass, Result(criticals, GateKeys.CriticalSast).Verdict);
        Assert.Equal(GateVerdict.Pass, Result(criticals, GateKeys.CriticalDast).Verdict);

        var highs = GateEvaluator.Evaluate(
            Gates((GateKeys.HighSast, null), (GateKeys.HighDast, null)), inputs, 20, null, null);
        Assert.Equal(GateVerdict.Fail, Result(highs, GateKeys.HighSast).Verdict);
        Assert.Equal(GateVerdict.Fail, Result(highs, GateKeys.HighDast).Verdict);
    }

    [Fact]
    public void High_gates_read_their_own_severity_bucket()
    {
        // A copy-paste slip would have highSast reading Critical, which would
        // put it right back in the unreachable state it exists to escape.
        var criticalOnly = Clean() with { SastCritical = 9, DastCritical = 9, SastHigh = 0, DastHigh = 0 };
        var eval = GateEvaluator.Evaluate(
            Gates((GateKeys.HighSast, null), (GateKeys.HighDast, null)), criticalOnly, 40, null, null);

        Assert.Equal(GateVerdict.Pass, Result(eval, GateKeys.HighSast).Verdict);
        Assert.Equal(GateVerdict.Pass, Result(eval, GateKeys.HighDast).Verdict);
    }

    [Fact]
    public void High_gates_do_not_cross_wire_sast_and_dast()
    {
        var sastOnly = Clean() with { SastHigh = 4, DastHigh = 0 };
        var eval = GateEvaluator.Evaluate(
            Gates((GateKeys.HighSast, null), (GateKeys.HighDast, null)), sastOnly, 20, null, null);

        Assert.Equal(GateVerdict.Fail, Result(eval, GateKeys.HighSast).Verdict);
        Assert.Equal(GateVerdict.Pass, Result(eval, GateKeys.HighDast).Verdict);
    }

    [Fact]
    public void High_gates_honour_a_threshold()
    {
        // A team with existing High debt can hold the line at today's count
        // instead of being forced to disable the gate entirely.
        var inputs = Clean() with { SastHigh = 5 };

        Assert.Equal(GateVerdict.Pass, Result(GateEvaluator.Evaluate(Gates((GateKeys.HighSast, 5)), inputs, 1, null, null),
            GateKeys.HighSast).Verdict);
        Assert.Equal(GateVerdict.Fail, Result(GateEvaluator.Evaluate(Gates((GateKeys.HighSast, 4)), inputs, 1, null, null),
            GateKeys.HighSast).Verdict);
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

    // ------------------------------------------------------------------
    // Four-valued verdicts (TFND-74 / ADR 0001)
    // ------------------------------------------------------------------
    //
    // The defect these exist for, quoted from ADR 0001:
    //
    //   "A project that has never been scanned PASSES every severity gate.
    //    criticalSast, highSast, criticalDast, highDast — all green,
    //    Failed = 0."
    //
    // The counts were zero because no scanner ran, and 0 <= 0 is a pass.
    // Two-valued logic had no way to say "I cannot answer that".

    // Nothing ran, nothing was found — the shape of a brand-new project
    // whose pipeline is not wired up yet.
    private static RiskInputs NeverScanned() => Clean() with
    {
        CoverageMeasured = false, TestsMeasured = false, SbomComponents = 0,
        RanSast = false, RanSecrets = false, RanIac = false,
        RanSbom = false, RanCoverage = false, RanDast = false, RanSca = false,
    };

    private static ProjectGatesConfig AllSeverityGates() => Gates(
        (GateKeys.CriticalSast, null), (GateKeys.HighSast, null),
        (GateKeys.CriticalDast, null), (GateKeys.HighDast, null),
        (GateKeys.CriticalCves, null), (GateKeys.HighCves, null),
        (GateKeys.KevExposure, null), (GateKeys.CriticalIac, null),
        (GateKeys.VerifiedSecrets, null), (GateKeys.DeniedLicenses, null));

    [Fact]
    public void An_unscanned_project_does_not_pass_the_severity_gates()
    {
        var eval = GateEvaluator.Evaluate(AllSeverityGates(), NeverScanned(), 0, null, null);

        // The regression test for the exact sentence in ADR 0001.
        Assert.Equal(0, eval.Passed);
        Assert.Equal(10, eval.Unknown);
        Assert.False(eval.ClearToShip);
    }

    // TFND-216: an SBOM is an inventory, not a vulnerability scan. A build with an SBOM but no SCA
    // scan (OSV/Grype) must NOT pass the CVE gates on "0 CVEs" — that zero is unassessed, not clean.
    [Theory]
    [InlineData(GateKeys.CriticalCves)]
    [InlineData(GateKeys.HighCves)]
    [InlineData(GateKeys.KevExposure)]
    public void An_sbom_without_an_sca_scan_leaves_the_cve_gates_unknown(string key)
    {
        var sbomButNoSca = Clean() with { RanSbom = true, SbomComponents = 42, RanSca = false };
        var eval = GateEvaluator.Evaluate(Gates((key, null)), sbomButNoSca, 0, null, null);
        var gate = Result(eval, key);
        Assert.Equal(GateVerdict.Unknown, gate.Verdict);
        Assert.True(gate.Blocks);
        Assert.Contains("scan", gate.Observed, StringComparison.Ordinal);
        // Denied licences, by contrast, ARE an inventory property — an SBOM alone answers them.
    }

    [Fact]
    public void Denied_licenses_still_answer_from_the_sbom_without_an_sca_scan()
    {
        var sbomButNoSca = Clean() with { RanSbom = true, SbomComponents = 42, RanSca = false };
        var eval = GateEvaluator.Evaluate(Gates((GateKeys.DeniedLicenses, null)), sbomButNoSca, 0, null, null);
        Assert.NotEqual(GateVerdict.Unknown, Result(eval, GateKeys.DeniedLicenses).Verdict);
    }

    [Theory]
    [InlineData(GateKeys.CriticalSast)]
    [InlineData(GateKeys.HighSast)]
    [InlineData(GateKeys.CriticalDast)]
    [InlineData(GateKeys.HighDast)]
    [InlineData(GateKeys.CriticalCves)]
    [InlineData(GateKeys.KevExposure)]
    [InlineData(GateKeys.CriticalIac)]
    [InlineData(GateKeys.VerifiedSecrets)]
    [InlineData(GateKeys.DeniedLicenses)]
    public void A_gate_whose_scanner_never_ran_is_unknown_and_blocks(string key)
    {
        var eval = GateEvaluator.Evaluate(Gates((key, null)), NeverScanned(), 0, null, null);

        var gate = Result(eval, key);
        Assert.Equal(GateVerdict.Unknown, gate.Verdict);
        Assert.True(gate.Blocks);
        // Unknown and Fail block for different reasons, so the prose has to
        // point at the pipeline rather than at findings that do not exist.
        // The bug being guarded is Observed reading "0 critical SAST" — a
        // count of zero that came from nobody looking.
        Assert.DoesNotContain("0 ", gate.Observed, StringComparison.Ordinal);
        Assert.Contains("scan", gate.Observed, StringComparison.Ordinal);
        Assert.Contains("nobody looked", gate.Reason!, StringComparison.Ordinal);
    }

    [Fact]
    public void Unknown_is_distinguishable_from_fail()
    {
        var unscanned = GateEvaluator.Evaluate(Gates((GateKeys.CriticalSast, null)), NeverScanned(), 0, null, null);
        var scanned   = GateEvaluator.Evaluate(Gates((GateKeys.CriticalSast, null)), Clean() with { SastCritical = 3 }, 0, null, null);

        // Both block, and that is the point: they are the same release
        // decision reached for different reasons, with different remedies.
        Assert.True(Result(unscanned, GateKeys.CriticalSast).Blocks);
        Assert.True(Result(scanned, GateKeys.CriticalSast).Blocks);
        Assert.NotEqual(
            Result(unscanned, GateKeys.CriticalSast).Verdict,
            Result(scanned, GateKeys.CriticalSast).Verdict);
    }

    [Fact]
    public void A_suite_that_never_ran_is_not_a_passing_suite()
    {
        // Same defect class as SSDF PW.8.1 answering "Yes" off a green test
        // run that did not exist.
        var eval = GateEvaluator.Evaluate(Gates((GateKeys.TestFailures, null)),
            Clean() with { TestsMeasured = false, TestsTotal = 0, TestsFailed = 0 }, 50, null, null);

        Assert.Equal(GateVerdict.Unknown, Result(eval, GateKeys.TestFailures).Verdict);
    }

    [Fact]
    public void Unmeasured_coverage_is_unknown_but_a_first_measurement_passes()
    {
        var unmeasured = GateEvaluator.Evaluate(Gates((GateKeys.CoverageRegression, null)),
            Clean() with { CoverageMeasured = false }, 50, null, null);
        Assert.Equal(GateVerdict.Unknown, Result(unmeasured, GateKeys.CoverageRegression).Verdict);

        // Coverage IS measured here; there is simply nothing earlier to
        // compare against. That is a real answer, not an inability to answer.
        var noPrior = GateEvaluator.Evaluate(Gates((GateKeys.CoverageRegression, null)),
            Clean(), 50, null, null);
        Assert.Equal(GateVerdict.Pass, Result(noPrior, GateKeys.CoverageRegression).Verdict);
    }

    [Fact]
    public void A_first_build_passes_the_regression_gate_rather_than_blocking_forever()
    {
        // Unknown here would block every brand-new project on its first build
        // until a second one exists — and "no prior build" is not a pipeline
        // defect anyone can fix.
        var eval = GateEvaluator.Evaluate(Gates((GateKeys.RiskScoreRegression, null)),
            Clean(), 42, null, null);

        var gate = Result(eval, GateKeys.RiskScoreRegression);
        Assert.Equal(GateVerdict.Pass, gate.Verdict);
        Assert.False(gate.Blocks);
    }

    [Fact]
    public void Poam_gates_are_answerable_without_any_scanner()
    {
        // POA&M items are user-entered records, not scanner output.
        var eval = GateEvaluator.Evaluate(Gates((GateKeys.PoamPastDue, null)),
            NeverScanned() with { OpenPastDuePoams = 2 }, 0, null, null);

        Assert.Equal(GateVerdict.Fail, Result(eval, GateKeys.PoamPastDue).Verdict);
    }

    [Fact]
    public void An_unimplemented_gate_key_is_an_error_and_blocks()
    {
        var eval = GateEvaluator.Evaluate(Gates(("notAGateKey", null)), Clean(), 50, null, null);

        // Never silently green: a gate the evaluator cannot implement is a
        // broken release contract, and an operator should hear about it.
        var gate = eval.Results.SingleOrDefault(r => r.Key == "notAGateKey");
        if (gate is not null)
        {
            Assert.Equal(GateVerdict.Error, gate.Verdict);
            Assert.True(gate.Blocks);
        }
    }

    [Fact]
    public void Enabled_count_is_derived_not_reconstructed_from_pass_plus_fail()
    {
        // The "9 gates enabled" bug: Passed + Failed silently drops every
        // Unknown, so an unscanned project reported fewer enabled gates than
        // it had.
        var eval = GateEvaluator.Evaluate(AllSeverityGates(), NeverScanned(), 0, null, null);

        Assert.Equal(10, eval.Enabled);
        Assert.NotEqual(eval.Enabled, eval.Passed + eval.Failed);
    }

    [Fact]
    public void A_fully_scanned_clean_project_is_clear_to_ship()
    {
        var eval = GateEvaluator.Evaluate(AllSeverityGates(), Clean(), 95, null, null);

        Assert.Equal(10, eval.Passed);
        Assert.Equal(0, eval.Unknown);
        Assert.Equal(0, eval.Blocking);
        Assert.True(eval.ClearToShip);
    }
}

    // TFND-182 additions ------------------------------------------------

    public class SbomAgeAndCoverageFloor
    {
        private static ProjectGatesConfig Gate(string key, double threshold)
        {
            var cfg = new ProjectGatesConfig();
            cfg.Gates[key] = new GateConfig { Enabled = true, Threshold = threshold };
            return cfg;
        }
        private static RiskInputs Base() => new(
            0, 0, 0, 0, KevListedCves: 0, SecretsVerified: 0, SecretsUnverified: 0,
            SastCritical: 0, SastHigh: 0, SastMedium: 0, SastLow: 0, IacCritical: 0, IacHigh: 0,
            CoverageMeasured: true, SequenceCoveragePercent: 85,
            SbomComponents: 10, SbomOutdated: 0, SbomStale: 0,
            TestsMeasured: true, TestsTotal: 100, TestsFailed: 0,
            LicenseDenied: 0, LicenseStrongCopyleft: 0, LicenseUnknown: 0,
            RanSast: true, RanSecrets: true, RanIac: true, RanSbom: true, RanCoverage: true, RanSca: true,
            RanDast: true, SbomAgeDays: 5);
        private static GateVerdict V(ProjectGatesConfig g, RiskInputs i, string key) =>
            GateEvaluator.Evaluate(g, i, 10, null, null).Results.Single(r => r.Key == key).Verdict;

        [Fact]
        public void Sbom_age_passes_within_and_fails_over()
        {
            Assert.Equal(GateVerdict.Pass, V(Gate(GateKeys.SbomAge, 30), Base() with { SbomAgeDays = 5 }, GateKeys.SbomAge));
            Assert.Equal(GateVerdict.Fail, V(Gate(GateKeys.SbomAge, 30), Base() with { SbomAgeDays = 60 }, GateKeys.SbomAge));
        }

        [Fact]
        public void Sbom_age_is_unknown_without_an_sbom_not_a_pass()
        {
            Assert.Equal(GateVerdict.Unknown, V(Gate(GateKeys.SbomAge, 30), Base() with { RanSbom = false, SbomAgeDays = null }, GateKeys.SbomAge));
        }

        [Fact]
        public void Coverage_floor_passes_at_or_above_and_fails_below()
        {
            Assert.Equal(GateVerdict.Pass, V(Gate(GateKeys.CoverageFloor, 70), Base() with { SequenceCoveragePercent = 85 }, GateKeys.CoverageFloor));
            Assert.Equal(GateVerdict.Fail, V(Gate(GateKeys.CoverageFloor, 70), Base() with { SequenceCoveragePercent = 60 }, GateKeys.CoverageFloor));
        }

        [Fact]
        public void Coverage_floor_is_unknown_when_unmeasured_not_a_pass()
        {
            Assert.Equal(GateVerdict.Unknown, V(Gate(GateKeys.CoverageFloor, 70), Base() with { CoverageMeasured = false }, GateKeys.CoverageFloor));
        }
    }

// TFND-184 — the intersection rule. A conditional gate the build's capability
// cannot produce is N/A (not run, not passed, NOT blocked), never a false pass.
public class GateIntersectionTests
{
    private static ProjectGatesConfig Gate(string key) =>
        new() { Gates = { [key] = new GateConfig { Enabled = true, Threshold = 0 } } };

    private static RiskInputs Inputs(bool ranDast) => new(
        0, 0, 0, 0, KevListedCves: 0, SecretsVerified: 0, SecretsUnverified: 0,
        SastCritical: 0, SastHigh: 0, SastMedium: 0, SastLow: 0, IacCritical: 0, IacHigh: 0,
        CoverageMeasured: true, SequenceCoveragePercent: 90,
        SbomComponents: 1, SbomOutdated: 0, SbomStale: 0,
        TestsMeasured: true, TestsTotal: 1, TestsFailed: 0,
        LicenseDenied: 0, LicenseStrongCopyleft: 0, LicenseUnknown: 0,
        RanSast: true, RanSecrets: true, RanIac: true, RanSbom: true, RanCoverage: true, RanSca: true,
        RanDast: ranDast);

    private static readonly Tamp.Findings.Domain.Compliance.ComponentCapability CodePackage =
        Tamp.Findings.Domain.Compliance.ComponentProfiles.Capabilities(Tamp.Findings.Domain.Compliance.ComponentProfile.CodePackage);
    private static readonly Tamp.Findings.Domain.Compliance.ComponentCapability Service =
        Tamp.Findings.Domain.Compliance.ComponentProfiles.Capabilities(Tamp.Findings.Domain.Compliance.ComponentProfile.Service);

    private static GateResult R(GateEvaluation e, string key) => e.Results.Single(r => r.Key == key);

    [Fact]
    public void A_dast_gate_on_a_code_package_is_not_applicable_and_does_not_block()
    {
        // A library never ran DAST — without the rule this would be Unknown (block).
        var eval = GateEvaluator.Evaluate(Gate(GateKeys.CriticalDast), Inputs(ranDast: false), 10, null, null, CodePackage);
        var r = R(eval, GateKeys.CriticalDast);
        Assert.Equal(GateVerdict.NotApplicable, r.Verdict);
        Assert.False(r.Blocks);
        Assert.True(eval.ClearToShip);
        Assert.Equal(1, eval.NotApplicable);
    }

    [Fact]
    public void An_iac_gate_on_a_code_package_is_not_applicable()
    {
        var eval = GateEvaluator.Evaluate(Gate(GateKeys.CriticalIac), Inputs(ranDast: false), 10, null, null, CodePackage);
        Assert.Equal(GateVerdict.NotApplicable, R(eval, GateKeys.CriticalIac).Verdict);
    }

    [Fact]
    public void A_dast_gate_on_a_service_is_evaluated_normally()
    {
        // A service CAN run DAST; a clean run passes, not N/A.
        var eval = GateEvaluator.Evaluate(Gate(GateKeys.CriticalDast), Inputs(ranDast: true), 10, null, null, Service);
        Assert.Equal(GateVerdict.Pass, R(eval, GateKeys.CriticalDast).Verdict);
    }

    [Fact]
    public void Without_a_capability_behaviour_is_unchanged()
    {
        // Null capability = assume everything applies: the old Unknown-on-no-DAST.
        var eval = GateEvaluator.Evaluate(Gate(GateKeys.CriticalDast), Inputs(ranDast: false), 10, null, null);
        Assert.Equal(GateVerdict.Unknown, R(eval, GateKeys.CriticalDast).Verdict);
    }
}
