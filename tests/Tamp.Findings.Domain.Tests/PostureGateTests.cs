using Tamp.Findings.Domain.Risk;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Domain.Tests;

// TFND-212: a producer-reported posture fact becomes a gate verdict — and absence or staleness is
// unassessed, never a silent pass.
public class PostureGateTests
{
    private static ProjectGatesConfig Gate(string key, double? maxAgeDays = null)
    {
        var cfg = new ProjectGatesConfig();
        cfg.Gates[key] = new GateConfig { Enabled = true, Threshold = maxAgeDays };
        return cfg;
    }

    private static RiskInputs Inputs(IReadOnlyDictionary<string, PostureReading>? posture) => new(
        0, 0, 0, 0, KevListedCves: 0,
        SecretsVerified: 0, SecretsUnverified: 0,
        SastCritical: 0, SastHigh: 0, SastMedium: 0, SastLow: 0,
        IacCritical: 0, IacHigh: 0,
        CoverageMeasured: true, SequenceCoveragePercent: 85,
        SbomComponents: 10, SbomOutdated: 0, SbomStale: 0,
        TestsMeasured: true, TestsTotal: 100, TestsFailed: 0,
        LicenseDenied: 0, LicenseStrongCopyleft: 0, LicenseUnknown: 0,
        RanSast: true, RanSecrets: true, RanIac: true, RanSbom: true, RanCoverage: true, RanSca: true,
        RanDast: true, Posture: posture);

    private static GateResult Run(string gate, RiskInputs i, double? maxAge = null) =>
        GateEvaluator.Evaluate(Gate(gate, maxAge), i, 1, null, null).Results.Single(r => r.Key == gate);

    private static Dictionary<string, PostureReading> One(string checkId, PostureStatus s, double ageDays = 1, string? detail = null) =>
        new() { [checkId] = new PostureReading(s, detail, DateTimeOffset.UtcNow.AddDays(-ageDays)) };

    [Fact]
    public void A_failed_check_fails_its_gate_and_shows_the_producers_evidence()
    {
        var r = Run(GateKeys.BranchProtection, Inputs(One("branch-protection", PostureStatus.Fail, detail: "force-push allowed")));
        Assert.Equal(GateVerdict.Fail, r.Verdict);
        Assert.Contains("force-push allowed", r.Observed);
    }

    [Fact]
    public void A_passing_check_passes()
    {
        var r = Run(GateKeys.SignedCommits, Inputs(One("signed-commits", PostureStatus.Pass)));
        Assert.Equal(GateVerdict.Pass, r.Verdict);
    }

    [Fact]
    public void Never_reported_is_unknown_not_a_pass()
    {
        Assert.Equal(GateVerdict.Unknown, Run(GateKeys.OrgTwoFactor, Inputs(null)).Verdict);
        Assert.Equal(GateVerdict.Unknown, Run(GateKeys.OrgTwoFactor, Inputs(new Dictionary<string, PostureReading>())).Verdict);
        Assert.Equal(GateVerdict.Unknown, Run(GateKeys.OrgTwoFactor, Inputs(One("org-2fa", PostureStatus.Unknown))).Verdict);
    }

    [Fact]
    public void An_observation_older_than_the_limit_is_unassessed_even_if_it_passed()
    {
        var old = Inputs(One("codeowners", PostureStatus.Pass, ageDays: 45));
        Assert.Equal(GateVerdict.Unknown, Run(GateKeys.Codeowners, old).Verdict);             // default 30 days
        Assert.Equal(GateVerdict.Pass, Run(GateKeys.Codeowners, old, maxAge: 60).Verdict);    // threshold = max age
    }

    [Fact]
    public void A_check_reported_not_applicable_does_not_block()
    {
        var r = Run(GateKeys.OrgTwoFactor, Inputs(One("org-2fa", PostureStatus.NotApplicable)));
        Assert.Equal(GateVerdict.NotApplicable, r.Verdict);
        Assert.False(r.Blocks);
    }

    [Fact]
    public void Each_check_reads_only_its_own_observation()
    {
        var posture = One("branch-protection", PostureStatus.Fail);
        Assert.Equal(GateVerdict.Unknown, Run(GateKeys.SignedCommits, Inputs(posture)).Verdict);
    }

    [Fact]
    public void Every_registered_check_has_a_gate_that_is_well_known_labelled_and_described()
    {
        foreach (var c in PostureChecks.All)
        {
            Assert.Contains(c.GateKey, GateEvaluator.WellKnownGateKeys);
            Assert.NotEqual(c.GateKey, GateEvaluator.Label(c.GateKey));            // a real label, not the raw key
            Assert.DoesNotContain("No description registered", GateEvaluator.Describe(c.GateKey));
            Assert.Equal(c, PostureChecks.ByGateKey(c.GateKey));
        }
    }

    [Fact]
    public void Posture_gates_are_off_by_default_so_no_baseline_blocks_on_a_producer_that_does_not_report_yet()
    {
        foreach (var layer in new[]
        {
            PolicyTemplateDefaults.BuildTampStandard(), PolicyTemplateDefaults.BuildFedRampLow(),
            PolicyTemplateDefaults.BuildFedRampModerate(), PolicyTemplateDefaults.BuildFedRampHigh(),
            PolicyTemplateDefaults.BuildGovRampCore(),
        })
        {
            foreach (var c in PostureChecks.All)
            {
                Assert.False(layer.Gates.TryGetValue(c.GateKey, out var g) && g.Enabled, $"{c.GateKey} must not be enabled by default");
                // ...and so, because a control is only mapped to a gate its template enables, none claims coverage it lacks.
                Assert.DoesNotContain(layer.Assertions, a => a.Gates.Contains(c.GateKey));
            }
        }
    }

    [Fact]
    public void Every_check_names_the_controls_it_evidences()
    {
        Assert.All(PostureChecks.All, c => Assert.NotEmpty(c.ControlRefs));
    }
}
