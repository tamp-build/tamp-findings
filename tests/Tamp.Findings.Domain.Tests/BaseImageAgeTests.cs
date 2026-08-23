using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Risk;

namespace Tamp.Findings.Domain.Tests;

// Base-image age (TFND-134).
//
// The gate has THREE ways of not knowing rather than one, and each calls for a
// different action. Collapsing them would tell a team to fix the wrong thing —
// which is most of what these assert.
public class BaseImageAgeTests
{
    private static ProjectGatesConfig Gated(int? threshold = null)
    {
        var config = ProjectGatesDefaults.Empty();
        config.Gates[GateKeys.BaseImageAge] = new GateConfig { Enabled = true, Threshold = threshold };
        return config;
    }

    private static RiskInputs Inputs(int? baseAgeDays, bool ranInspect) =>
        new(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            CoverageMeasured: true, SequenceCoveragePercent: 100,
            SbomComponents: 0, SbomOutdated: 0, SbomStale: 0,
            TestsMeasured: true, TestsTotal: 1, TestsFailed: 0,
            LicenseDenied: 0, LicenseStrongCopyleft: 0, LicenseUnknown: 0,
            RanSast: true, RanSecrets: true, RanIac: true, RanSbom: true, RanCoverage: true,
            BaseImageAgeDays: baseAgeDays, RanImageInspect: ranInspect);

    private static GateResult Evaluate(int? baseAgeDays, bool ranInspect, int? threshold = null) =>
        GateEvaluator.Evaluate(Gated(threshold), Inputs(baseAgeDays, ranInspect), 0, null, null)
            .Results.Single(g => g.Key == GateKeys.BaseImageAge);

    // ---- The three ways of not knowing ---------------------------------------

    [Fact]
    public void No_image_inspected_is_unknown_not_pass()
    {
        // An unmeasured base image is not a fresh one — the same rule as every
        // other gate here, and the reason ADR 0001 has four verdicts.
        var gate = Evaluate(baseAgeDays: null, ranInspect: false);

        Assert.Equal(GateVerdict.Unknown, gate.Verdict);
        Assert.Contains("no container image was inspected", gate.Reason!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void An_inspected_image_with_an_unidentified_base_is_a_different_unknown()
    {
        // THE common case, and the one worth distinguishing. The pipeline is
        // wired up correctly; the base image simply is not named, because the
        // OCI annotation that carries it is usually absent. Telling this team
        // to "add an image inspect" would send them to fix something that is
        // already working.
        var gate = Evaluate(baseAgeDays: null, ranInspect: true);

        Assert.Equal(GateVerdict.Unknown, gate.Verdict);
        Assert.Contains("could not be identified", gate.Reason!, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("no container image was inspected", gate.Reason!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void The_unknown_reasons_do_not_suggest_guessing_the_base_from_layers()
    {
        // Deliberate: inferring a base image from layer history produces a
        // confident wrong answer, and this dashboard would present it as a
        // fact. The message says so rather than leaving it as a good idea
        // somebody has later.
        var gate = Evaluate(baseAgeDays: null, ranInspect: true);

        Assert.Contains("layer history", gate.Reason!, StringComparison.OrdinalIgnoreCase);
    }

    // ---- When it can answer --------------------------------------------------

    [Fact]
    public void A_recent_base_image_passes()
    {
        Assert.Equal(GateVerdict.Pass, Evaluate(baseAgeDays: 30, ranInspect: true).Verdict);
    }

    [Fact]
    public void A_base_image_past_the_threshold_fails()
    {
        Assert.Equal(GateVerdict.Fail, Evaluate(baseAgeDays: 400, ranInspect: true).Verdict);
    }

    [Fact]
    public void The_default_threshold_is_a_year()
    {
        // A year rather than something tighter: base images are republished on
        // their own cadence, and a gate that fires monthly is a gate people
        // turn off.
        Assert.Equal(GateVerdict.Pass, Evaluate(baseAgeDays: 364, ranInspect: true).Verdict);
        Assert.Equal(GateVerdict.Fail, Evaluate(baseAgeDays: 366, ranInspect: true).Verdict);
    }

    [Fact]
    public void The_threshold_is_configurable()
    {
        Assert.Equal(GateVerdict.Fail, Evaluate(baseAgeDays: 100, ranInspect: true, threshold: 90).Verdict);
        Assert.Equal(GateVerdict.Pass, Evaluate(baseAgeDays: 100, ranInspect: true, threshold: 180).Verdict);
    }

    [Fact]
    public void The_observed_value_says_at_build_rather_than_now()
    {
        // The number is measured at the build, so the label has to say so —
        // otherwise a reader assumes it drifts with the calendar and treats a
        // stable number as a stale page.
        var gate = Evaluate(baseAgeDays: 400, ranInspect: true);

        Assert.Contains("at build", gate.Observed!, StringComparison.OrdinalIgnoreCase);
    }

    // ---- The score ----------------------------------------------------------

    [Fact]
    public void An_unknown_base_image_scores_zero_rather_than_a_penalty()
    {
        // The GATE is where "nobody looked" becomes visible, not the score. A
        // score that penalised an unmeasured base image would make every
        // project without container builds look worse than it is — and most
        // projects on an instance have no image at all.
        var policy = RiskPolicyDefaults.BuildTampFederalV1();

        var scored = RiskScorer.Compute(policy, Inputs(baseAgeDays: null, ranInspect: false));
        var row = scored.Breakdown.Single(r => r.Key == RiskCategoryNames.BaseImageAge);

        Assert.Equal(0, row.Contribution, precision: 6);
    }

    [Fact]
    public void A_base_image_inside_the_grace_period_scores_zero()
    {
        // Ninety days. Flagging a base image the week after a release would
        // train teams to ignore the category.
        var policy = RiskPolicyDefaults.BuildTampFederalV1();

        var row = RiskScorer.Compute(policy, Inputs(60, true))
            .Breakdown.Single(r => r.Key == RiskCategoryNames.BaseImageAge);

        Assert.Equal(0, row.Contribution, precision: 6);
    }

    [Fact]
    public void The_score_climbs_between_the_grace_period_and_the_ceiling()
    {
        var policy = RiskPolicyDefaults.BuildTampFederalV1();

        double Raw(int days) => RiskScorer.Compute(policy, Inputs(days, true))
            .Breakdown.Single(r => r.Key == RiskCategoryNames.BaseImageAge).Contribution;

        Assert.True(Raw(180) > Raw(120));
        Assert.True(Raw(300) > Raw(180));
    }

    [Fact]
    public void The_score_stops_climbing_past_the_ceiling()
    {
        // Past a year the answer is already "replace this". Letting it keep
        // climbing would let one ancient base image swamp every other category.
        var policy = RiskPolicyDefaults.BuildTampFederalV1();

        double Raw(int days) => RiskScorer.Compute(policy, Inputs(days, true))
            .Breakdown.Single(r => r.Key == RiskCategoryNames.BaseImageAge).Contribution;

        Assert.Equal(Raw(365), Raw(3650), precision: 6);
    }

    [Fact]
    public void The_standard_policy_does_not_carry_the_category()
    {
        // Schema 1 has a fixed 100-point budget, so adding a category there
        // would overflow it rather than redistribute. A v2 policy normalises,
        // which is the point of having one.
        Assert.DoesNotContain(
            RiskCategoryNames.BaseImageAge,
            RiskPolicyDefaults.BuildTampStandardV1().Categories.Keys);

        Assert.Contains(
            RiskCategoryNames.BaseImageAge,
            RiskPolicyDefaults.BuildTampFederalV1().Categories.Keys);
    }

    // ---- The entity ---------------------------------------------------------

    [Fact]
    public void Age_on_the_entity_is_measured_at_the_inspect_not_at_now()
    {
        var image = new ContainerImage
        {
            Reference = "registry.example/app:1.0",
            ComponentVersionId = Guid.NewGuid(),
            BaseImageCreatedAt = new DateTimeOffset(2025, 1, 1, 0, 0, 0, TimeSpan.Zero),
            InspectedAt = new DateTimeOffset(2025, 4, 1, 0, 0, 0, TimeSpan.Zero),
        };

        Assert.Equal(90, image.BaseImageAgeInDays);
    }

    [Fact]
    public void An_unknown_base_creation_date_is_an_unknown_age_not_zero()
    {
        // Zero would say "published today", which is the opposite of what an
        // absent timestamp means.
        var image = new ContainerImage
        {
            Reference = "registry.example/app:1.0",
            ComponentVersionId = Guid.NewGuid(),
            BaseImageCreatedAt = null,
        };

        Assert.Null(image.BaseImageAgeInDays);
    }

    [Fact]
    public void Clock_skew_does_not_produce_a_negative_age()
    {
        // A base published a few seconds "after" the build is normal clock
        // skew between an agent and a registry, and a negative age reads as a
        // bug rather than as the skew it is.
        var image = new ContainerImage
        {
            Reference = "registry.example/app:1.0",
            ComponentVersionId = Guid.NewGuid(),
            BaseImageCreatedAt = new DateTimeOffset(2025, 4, 1, 0, 0, 0, TimeSpan.Zero),
            InspectedAt = new DateTimeOffset(2025, 3, 31, 23, 59, 0, TimeSpan.Zero),
        };

        Assert.Equal(0, image.BaseImageAgeInDays);
    }
}
