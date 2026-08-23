using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Risk;

namespace Tamp.Findings.Domain.Tests;

// Locks in the SchemaVersion 1 -> 2 migration. The load-bearing test is
// V1_and_v2_agree_exactly_for_a_well_formed_policy: the normalised scorer
// must be a no-op for Tamp Standard v1, which is what makes the change
// safe to ship against live projects and signed attestations.
public class RiskScorerTests
{
    // ------------------------------------------------------------------
    // v1 / v2 equivalence — the migration safety net
    // ------------------------------------------------------------------

    // Tamp Standard v1 enables every category and its weights sum to
    // exactly 100, so normalising divides by 100 and multiplies by 100.
    // Any drift here means the migration silently rescored someone.
    [Theory]
    [MemberData(nameof(InputMatrix))]
    public void V1_and_v2_agree_exactly_for_a_well_formed_policy(RiskInputs inputs)
    {
        var v1 = RiskPolicyDefaults.BuildTampStandardV1();
        var v2 = RiskPolicyDefaults.BuildTampStandardV1();
        v2.SchemaVersion = 2;

        var a = RiskScorer.Compute(v1, inputs);
        var b = RiskScorer.Compute(v2, inputs);

        Assert.Equal(a.Score, b.Score, precision: 10);
        Assert.Equal(a.Band, b.Band);
    }

    [Fact]
    public void Tamp_standard_v1_weights_sum_to_one_hundred()
    {
        // The equivalence above only holds because of this. If someone
        // rebalances the seed without keeping the sum at 100, this fails
        // first and explains why.
        var policy = RiskPolicyDefaults.BuildTampStandardV1();
        var sum = policy.Categories.Values.Where(c => c.Enabled).Sum(c => c.Max);
        Assert.Equal(100, sum, precision: 10);
    }

    [Theory]
    [MemberData(nameof(InputMatrix))]
    public void Effective_max_equals_authored_max_for_a_well_formed_v1_policy(RiskInputs inputs)
    {
        var policy = RiskPolicyDefaults.BuildTampStandardV1();
        policy.SchemaVersion = 2;

        var result = RiskScorer.Compute(policy, inputs);

        foreach (var row in result.Breakdown.Where(r => r.Enabled))
        {
            Assert.Equal(row.Max, row.EffectiveMax, precision: 10);
        }
    }

    // ------------------------------------------------------------------
    // The bug v2 exists to fix
    // ------------------------------------------------------------------

    // Under v1, switching a check OFF lowers the score — the numerator
    // loses the category but the denominator is hardcoded at 100. This
    // test documents the old behaviour rather than endorsing it.
    [Fact]
    public void V1_deflates_the_score_when_a_category_is_disabled()
    {
        var inputs = DirtyProject();

        var all = RiskPolicyDefaults.BuildTampStandardV1();
        var without = RiskPolicyDefaults.BuildTampStandardV1();
        without.Categories[RiskCategoryNames.IacSevere].Enabled = false;

        var withScore = RiskScorer.Compute(all, inputs).Score;
        var withoutScore = RiskScorer.Compute(without, inputs).Score;

        Assert.True(withoutScore < withScore,
            $"expected v1 to deflate on disable, got {withoutScore} vs {withScore}");
    }

    // Under v2 the disabled category's share redistributes across the
    // rest, so a project with problems elsewhere does not look safer
    // merely because a check was turned off.
    [Fact]
    public void V2_redistributes_rather_than_deflates_when_a_category_is_disabled()
    {
        // Inputs are clean on IaC specifically, so disabling iacSevere
        // removes a zero-contribution category. Under v1 that still drags
        // the score down; under v2 the remaining categories expand.
        var inputs = DirtyProject() with { IacCritical = 0, IacHigh = 0 };

        var all = RiskPolicyDefaults.BuildTampStandardV1();
        all.SchemaVersion = 2;
        var without = RiskPolicyDefaults.BuildTampStandardV1();
        without.SchemaVersion = 2;
        without.Categories[RiskCategoryNames.IacSevere].Enabled = false;

        var withScore = RiskScorer.Compute(all, inputs).Score;
        var withoutScore = RiskScorer.Compute(without, inputs).Score;

        Assert.True(withoutScore > withScore,
            $"expected v2 to redistribute upward, got {withoutScore} vs {withScore}");
    }

    [Fact]
    public void V2_weight_scale_is_arbitrary()
    {
        // 10/20/30 must score identically to 1/2/3 — the whole point of
        // Max becoming a relative weight.
        var inputs = DirtyProject();

        var baseline = RiskPolicyDefaults.BuildTampStandardV1();
        baseline.SchemaVersion = 2;

        var scaled = RiskPolicyDefaults.BuildTampStandardV1();
        scaled.SchemaVersion = 2;
        foreach (var cat in scaled.Categories.Values) cat.Max *= 7.5;

        Assert.Equal(
            RiskScorer.Compute(baseline, inputs).Score,
            RiskScorer.Compute(scaled, inputs).Score,
            precision: 10);
    }

    [Fact]
    public void Weight_basis_reports_the_enabled_sum()
    {
        var policy = RiskPolicyDefaults.BuildTampStandardV1();
        policy.SchemaVersion = 2;
        policy.Categories[RiskCategoryNames.IacSevere].Enabled = false;   // Max 10

        var result = RiskScorer.Compute(policy, CleanProject());

        Assert.Equal(90, result.WeightBasis, precision: 10);
    }

    // ------------------------------------------------------------------
    // Edge cases
    // ------------------------------------------------------------------

    [Fact]
    public void All_categories_disabled_scores_zero_without_dividing_by_zero()
    {
        var policy = RiskPolicyDefaults.BuildTampStandardV1();
        policy.SchemaVersion = 2;
        foreach (var cat in policy.Categories.Values) cat.Enabled = false;

        var result = RiskScorer.Compute(policy, DirtyProject());

        Assert.Equal(0, result.Score);
        Assert.Equal(0, result.WeightBasis);
        // Zero basis is the caller's cue to render "unscored" rather than
        // a green 0%.
        Assert.All(result.Breakdown, r => Assert.False(r.Enabled));
    }

    [Fact]
    public void Unsupported_schema_versions_throw()
    {
        var policy = RiskPolicyDefaults.BuildTampStandardV1();
        policy.SchemaVersion = RiskScorer.MaxSupportedSchemaVersion + 1;

        Assert.Throws<InvalidOperationException>(() => RiskScorer.Compute(policy, CleanProject()));
    }

    // Sub-scores clamp to 1.0, so a category saturates and stops
    // responding. Undocumented and untested before now, and load-bearing:
    // it's what stops one noisy scanner from dominating the score.
    [Fact]
    public void Categories_saturate_and_stop_responding_to_additional_findings()
    {
        var policy = RiskPolicyDefaults.BuildTampStandardV1();

        // cve critical weight is 0.50, so two criticals reach sub-score 1.0.
        var two = RiskScorer.Compute(policy, CleanProject() with { CveCritical = 2 });
        var twoHundred = RiskScorer.Compute(policy, CleanProject() with { CveCritical = 200 });

        Assert.Equal(two.Score, twoHundred.Score, precision: 10);

        var row = two.Breakdown.Single(r => r.Key == RiskCategoryNames.Cve);
        Assert.Equal(1.0, row.SubScore, precision: 10);
        Assert.Equal(25, row.Contribution, precision: 10);
    }

    // ------------------------------------------------------------------
    // missingScanners
    // ------------------------------------------------------------------

    [Theory]
    [InlineData(0, 0.0)]
    [InlineData(1, 0.2)]
    [InlineData(3, 0.6)]
    [InlineData(5, 1.0)]
    public void Missing_scanners_with_no_weights_reproduces_the_legacy_five_class_fraction(
        int missingCount, double expectedSubScore)
    {
        var policy = RiskPolicyDefaults.BuildTampStandardV1();
        Assert.Empty(policy.Categories[RiskCategoryNames.MissingScanners].Weights);

        var flags = new[] { true, true, true, true, true };
        for (var n = 0; n < missingCount; n++) flags[n] = false;

        var inputs = CleanProject() with
        {
            RanSast = flags[0], RanSecrets = flags[1], RanIac = flags[2],
            RanSbom = flags[3], RanCoverage = flags[4],
            // DAST absent must not count against a legacy policy.
            RanDast = false,
        };

        var row = RiskScorer.Compute(policy, inputs).Breakdown
            .Single(r => r.Key == RiskCategoryNames.MissingScanners);

        Assert.Equal(expectedSubScore, row.SubScore, precision: 10);
    }

    [Fact]
    public void Missing_scanners_ignores_classes_weighted_zero()
    {
        // A pure library: no IaC surface, nothing deployed to scan.
        // Neither absence should count against it.
        var policy = RiskPolicyDefaults.BuildTampFederalV1();
        var weights = policy.Categories[RiskCategoryNames.MissingScanners].Weights;
        weights[ExpectedScannerKeys.Iac] = 0;
        weights[ExpectedScannerKeys.Dast] = 0;

        var inputs = CleanProject() with
        {
            RanSast = true, RanSecrets = true, RanSbom = true, RanCoverage = true,
            RanIac = false, RanDast = false,
        };

        var row = RiskScorer.Compute(policy, inputs).Breakdown
            .Single(r => r.Key == RiskCategoryNames.MissingScanners);

        Assert.Equal(0, row.SubScore, precision: 10);
    }

    [Fact]
    public void Missing_scanners_counts_dast_when_the_policy_expects_it()
    {
        var policy = RiskPolicyDefaults.BuildTampFederalV1();

        var inputs = CleanProject() with
        {
            RanSast = true, RanSecrets = true, RanIac = true,
            RanSbom = true, RanCoverage = true, RanDast = false,
        };

        var row = RiskScorer.Compute(policy, inputs).Breakdown
            .Single(r => r.Key == RiskCategoryNames.MissingScanners);

        // One of six expected classes absent.
        Assert.Equal(1.0 / 6.0, row.SubScore, precision: 10);
    }

    // ------------------------------------------------------------------
    // DAST categories
    // ------------------------------------------------------------------

    [Fact]
    public void Dast_findings_do_not_score_under_a_policy_without_dast_categories()
    {
        // Tamp Standard v1 has no dast categories, so DAST findings are
        // inert there. This is the pre-existing behaviour and it stays
        // until a project opts into the Federal policy.
        var policy = RiskPolicyDefaults.BuildTampStandardV1();

        var without = RiskScorer.Compute(policy, CleanProject());
        var with = RiskScorer.Compute(policy, CleanProject() with { DastCritical = 5, DastHigh = 20 });

        Assert.Equal(without.Score, with.Score, precision: 10);
    }

    [Fact]
    public void Dast_findings_score_under_the_federal_policy()
    {
        var policy = RiskPolicyDefaults.BuildTampFederalV1();

        var clean = RiskScorer.Compute(policy, CleanProject());
        var dirty = RiskScorer.Compute(policy, CleanProject() with { DastCritical = 2 });

        Assert.True(dirty.Score > clean.Score);

        var row = dirty.Breakdown.Single(r => r.Key == RiskCategoryNames.DastSevere);
        Assert.Equal(1.0, row.SubScore, precision: 10);   // 2 x 0.50 saturates
    }

    [Fact]
    public void Dast_severe_carries_the_same_weight_as_sast_severe_per_finding()
    {
        // A runtime-confirmed finding must not score softer than a static
        // pattern match against the same weakness. Weights match; only the
        // category budget differs (15 vs 12).
        var policy = RiskPolicyDefaults.BuildTampFederalV1();
        var sast = policy.Categories[RiskCategoryNames.SastSevere].Weights;
        var dast = policy.Categories[RiskCategoryNames.DastSevere].Weights;

        Assert.Equal(sast["critical"], dast["critical"]);
        Assert.Equal(sast["high"], dast["high"]);
    }

    [Fact]
    public void Federal_policy_effective_maxima_normalise_to_one_hundred()
    {
        var policy = RiskPolicyDefaults.BuildTampFederalV1();

        var result = RiskScorer.Compute(policy, CleanProject());
        var totalEffective = result.Breakdown.Where(r => r.Enabled).Sum(r => r.EffectiveMax);

        // Normalisation to 100 is the invariant; the BASIS is just the sum of
        // authored weights and moves whenever a category is added. It went from
        // 114 to 116 when TFND-33 … TFND-37 added the quality category — and
        // the point of a v2 policy is that adding one REDISTRIBUTES rather than
        // overflowing, which is exactly what the first assertion proves.
        Assert.Equal(100, totalEffective, precision: 8);
        Assert.Equal(116, result.WeightBasis, precision: 10);
    }

    [Fact]
    public void Federal_policy_is_schema_version_two()
    {
        Assert.Equal(2, RiskPolicyDefaults.BuildTampFederalV1().SchemaVersion);
    }

    // ------------------------------------------------------------------
    // Fixtures
    // ------------------------------------------------------------------

    // Every scanner ran, nothing found, coverage at target. Scores near
    // zero under both policies so a test can isolate one input.
    private static RiskInputs CleanProject() => new(
        CveCritical: 0, CveHigh: 0, CveMedium: 0, CveLow: 0,
        KevListedCves: 0,
        SecretsVerified: 0, SecretsUnverified: 0,
        SastCritical: 0, SastHigh: 0, SastMedium: 0, SastLow: 0,
        IacCritical: 0, IacHigh: 0,
        CoverageMeasured: true, SequenceCoveragePercent: 85,
        SbomComponents: 100, SbomOutdated: 0, SbomStale: 0,
        TestsMeasured: true, TestsTotal: 500, TestsFailed: 0,
        LicenseDenied: 0, LicenseStrongCopyleft: 0, LicenseUnknown: 0,
        RanSast: true, RanSecrets: true, RanIac: true, RanSbom: true, RanCoverage: true,
        OpenPastDuePoams: 0,
        DastCritical: 0, DastHigh: 0, DastMedium: 0, DastLow: 0, RanDast: true);

    private static RiskInputs DirtyProject() => CleanProject() with
    {
        CveCritical = 1, CveHigh = 4, CveMedium = 12,
        SecretsUnverified = 2,
        SastCritical = 1, SastHigh = 3, SastMedium = 40,
        IacCritical = 1, IacHigh = 2,
        SequenceCoveragePercent = 52,
        SbomOutdated = 22, SbomStale = 6,
        TestsFailed = 3,
        LicenseStrongCopyleft = 2, LicenseUnknown = 9,
        DastCritical = 1, DastHigh = 2, DastMedium = 15,
    };

    public static TheoryData<RiskInputs> InputMatrix() =>
    [
        CleanProject(),
        DirtyProject(),
        // Nothing ran at all — exercises every unmeasured/missing branch.
        CleanProject() with
        {
            CoverageMeasured = false, TestsMeasured = false, SbomComponents = 0,
            RanSast = false, RanSecrets = false, RanIac = false,
            RanSbom = false, RanCoverage = false, RanDast = false,
        },
        // Saturated across the board — every category clamps at 1.0.
        CleanProject() with
        {
            CveCritical = 50, SecretsVerified = 5,
            SastCritical = 10, SastMedium = 5000,
            IacCritical = 10,
            CoverageMeasured = true, SequenceCoveragePercent = 0,
            SbomComponents = 100, SbomOutdated = 100, SbomStale = 100,
            TestsMeasured = true, TestsTotal = 100, TestsFailed = 100,
            LicenseDenied = 20, LicenseUnknown = 100,
        },
        // Boundary: exactly at the green/yellow band edge inputs.
        CleanProject() with { CveHigh = 1, SastHigh = 1 },
    ];

    // ------------------------------------------------------------------
    // Saturation (TFND-76)
    // ------------------------------------------------------------------
    //
    // The project hub renders saturation twice on one row — a SAT chip and
    // a red bar fill — and routes off it. These pin the meaning so the two
    // cannot drift from each other or from the score.

    [Fact]
    public void A_clean_project_saturates_nothing()
    {
        var policy = RiskPolicyDefaults.BuildTampStandardV1();

        var result = RiskScorer.Compute(policy, CleanProject());

        Assert.All(result.Breakdown, r => Assert.False(r.Saturated));
    }

    [Fact]
    public void A_category_at_its_ceiling_is_saturated()
    {
        var policy = RiskPolicyDefaults.BuildTampStandardV1();
        // 50 critical CVEs is far past any sane ceiling for that category.
        var result = RiskScorer.Compute(policy, CleanProject() with { CveCritical = 50 });

        var cve = result.Breakdown.Single(r => r.Key == RiskCategoryNames.Cve);
        Assert.True(cve.Saturated);
        Assert.Equal(1.0, cve.SubScore, precision: 10);
        // Saturated means the ceiling was reached, so the category costs
        // exactly its effective max and no more.
        Assert.Equal(cve.EffectiveMax, cve.Contribution, precision: 10);
    }

    [Fact]
    public void Saturation_means_more_findings_cannot_cost_more()
    {
        var policy = RiskPolicyDefaults.BuildTampStandardV1();

        var some = RiskScorer.Compute(policy, CleanProject() with { CveCritical = 50 });
        var many = RiskScorer.Compute(policy, CleanProject() with { CveCritical = 500 });

        var a = some.Breakdown.Single(r => r.Key == RiskCategoryNames.Cve);
        var b = many.Breakdown.Single(r => r.Key == RiskCategoryNames.Cve);

        Assert.True(a.Saturated);
        Assert.True(b.Saturated);
        // This is the sentence the hub prints under the table: the score is
        // posture, not volume.
        Assert.Equal(a.Contribution, b.Contribution, precision: 10);
    }

    [Fact]
    public void A_disabled_category_is_never_saturated()
    {
        var policy = RiskPolicyDefaults.BuildTampStandardV1();
        policy.Categories[RiskCategoryNames.Cve].Enabled = false;

        var result = RiskScorer.Compute(policy, CleanProject() with { CveCritical = 500 });

        var cve = result.Breakdown.Single(r => r.Key == RiskCategoryNames.Cve);
        Assert.False(cve.Enabled);
        Assert.False(cve.Saturated);
    }

    [Theory]
    [MemberData(nameof(InputMatrix))]
    public void Saturation_agrees_with_the_clamped_sub_score(RiskInputs inputs)
    {
        var policy = RiskPolicyDefaults.BuildTampStandardV1();

        var result = RiskScorer.Compute(policy, inputs);

        // The invariant a UI would otherwise re-derive with a floating-point
        // comparison of its own. If this ever fails, every consumer that
        // trusted SubScore >= 1 was already wrong.
        foreach (var row in result.Breakdown.Where(r => r.Enabled))
        {
            Assert.Equal(row.SubScore >= 1.0, row.Saturated);
        }
    }
}
