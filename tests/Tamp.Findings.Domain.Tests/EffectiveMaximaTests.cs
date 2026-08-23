using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Risk;

namespace Tamp.Findings.Domain.Tests;

// Effective maxima (TFND-105).
//
// The policy editor exists to demonstrate one thing a static table cannot:
// A CATEGORY'S CEILING IS NOT A FIXED NUMBER. These pin the behaviour it
// demonstrates, so the editor can never be showing a normalisation the scorer
// does not actually perform.
public class EffectiveMaximaTests
{
    private static RiskPolicyConfig Policy(int schema, params (string Key, double Max, bool On)[] categories)
    {
        var config = new RiskPolicyConfig { SchemaVersion = schema };
        foreach (var (key, max, on) in categories)
            config.Categories[key] = new RiskCategoryConfig { Enabled = on, Max = max };
        return config;
    }

    [Fact]
    public void A_well_formed_v1_policy_has_effective_maxima_equal_to_its_weights()
    {
        // Under schema 1 the denominator is a fixed 100, so a policy whose
        // weights already sum to 100 sees no normalisation at all. That is the
        // case people picture when they think a ceiling is fixed.
        var policy = Policy(1, ("cve", 40, true), ("sastSevere", 60, true));

        var maxima = RiskScorer.EffectiveMaxima(policy);

        Assert.Equal(40, maxima["cve"], 3);
        Assert.Equal(60, maxima["sastSevere"], 3);
    }

    [Fact]
    public void Under_v2_weights_are_relative_and_normalise_to_a_hundred()
    {
        var policy = Policy(2, ("cve", 1, true), ("sastSevere", 3, true));

        var maxima = RiskScorer.EffectiveMaxima(policy);

        Assert.Equal(25, maxima["cve"], 3);
        Assert.Equal(75, maxima["sastSevere"], 3);
    }

    [Fact]
    public void Disabling_a_category_redistributes_its_share_rather_than_deflating_the_score()
    {
        // The whole point of the screen. Three equal categories at 33.3 each;
        // switch one off and the other two go to 50, not stay at 33.3 with a
        // third of the score unreachable.
        var policy = Policy(2, ("cve", 1, true), ("sastSevere", 1, true), ("coverage", 1, true));

        Assert.Equal(33.333, RiskScorer.EffectiveMaxima(policy)["cve"], 2);

        policy.Categories["coverage"].Enabled = false;

        var after = RiskScorer.EffectiveMaxima(policy);
        Assert.Equal(50, after["cve"], 3);
        Assert.Equal(50, after["sastSevere"], 3);
        Assert.Equal(0, after["coverage"], 3);
    }

    [Fact]
    public void Raising_one_weight_lowers_every_other_ceiling()
    {
        var policy = Policy(2, ("cve", 1, true), ("sastSevere", 1, true));
        Assert.Equal(50, RiskScorer.EffectiveMaxima(policy)["sastSevere"], 3);

        policy.Categories["cve"].Max = 3;

        Assert.Equal(25, RiskScorer.EffectiveMaxima(policy)["sastSevere"], 3);
    }

    [Fact]
    public void A_disabled_category_has_a_ceiling_of_zero_whatever_its_weight_says()
    {
        var policy = Policy(2, ("cve", 90, false), ("sastSevere", 10, true));

        Assert.Equal(0, RiskScorer.EffectiveMaxima(policy)["cve"], 3);
        // And the enabled one takes the whole budget.
        Assert.Equal(100, RiskScorer.EffectiveMaxima(policy)["sastSevere"], 3);
    }

    [Fact]
    public void A_zero_weight_category_contributes_nothing_even_when_enabled()
    {
        var policy = Policy(2, ("cve", 0, true), ("sastSevere", 10, true));

        Assert.Equal(0, RiskScorer.EffectiveMaxima(policy)["cve"], 3);
    }

    [Fact]
    public void A_policy_with_nothing_enabled_has_no_ceilings_rather_than_dividing_by_zero()
    {
        var policy = Policy(2, ("cve", 40, false), ("sastSevere", 60, false));

        var maxima = RiskScorer.EffectiveMaxima(policy);

        Assert.Equal(0, maxima["cve"], 3);
        Assert.Equal(0, maxima["sastSevere"], 3);
    }

    [Fact]
    public void The_basis_counts_only_enabled_categories()
    {
        var policy = Policy(2, ("cve", 40, true), ("sastSevere", 60, false));

        Assert.Equal(40, RiskScorer.WeightBasis(policy), 3);
    }

    [Fact]
    public void The_maxima_the_editor_shows_are_the_ones_the_scorer_applies()
    {
        // The reason EffectiveMaxima lives on RiskScorer rather than in the
        // editor: two implementations would eventually disagree, and the editor
        // would then be demonstrating a normalisation that does not happen.
        var policy = Policy(2, ("cve", 1, true), ("sastSevere", 3, true));

        var standalone = RiskScorer.EffectiveMaxima(policy);
        var computed = RiskScorer.Compute(policy, CleanProject());

        foreach (var row in computed.Breakdown)
            Assert.Equal(standalone[row.Key], row.EffectiveMax, 3);
    }

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
    }
