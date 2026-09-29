using Tamp.Findings.Domain.Compliance;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Risk;

namespace Tamp.Findings.Domain.Tests;

// Archetype-aware scoring (TFND-203 follow-up). A category whose evidence the component cannot
// produce must drop out of the weight basis rather than sit there as a permanent 0/N — the same
// way the gates already treat it as N/A.
public class ArchetypeScoringTests
{
    private const ComponentCapability Library = ComponentCapability.Source | ComponentCapability.Deps;
    private const ComponentCapability Service =
        ComponentCapability.Source | ComponentCapability.Deps | ComponentCapability.Image
        | ComponentCapability.Web | ComponentCapability.Iac;

    private static RiskPolicyConfig Policy()
    {
        var c = new RiskPolicyConfig { SchemaVersion = 2 };
        c.Categories[RiskCategoryNames.Cve] = new RiskCategoryConfig { Enabled = true, Max = 25 };
        c.Categories[RiskCategoryNames.SastSevere] = new RiskCategoryConfig { Enabled = true, Max = 15 };
        c.Categories[RiskCategoryNames.IacSevere] = new RiskCategoryConfig { Enabled = true, Max = 10 };
        c.Categories[RiskCategoryNames.MissingScanners] = new RiskCategoryConfig
        {
            Enabled = true, Max = 2,
            Weights = new() { ["sast"] = 1, ["iac"] = 1, ["dast"] = 1 },
        };
        return c;
    }

    [Fact]
    public void A_library_drops_iac_and_the_rest_redistribute()
    {
        var cveBefore = RiskScorer.EffectiveMaxima(Policy())[RiskCategoryNames.Cve];

        var lib = Policy();
        ArchetypeScoring.ApplyCapability(lib, Library);

        Assert.False(lib.Categories.ContainsKey(RiskCategoryNames.IacSevere));
        // The basis shrank by IaC's weight, so every applicable category's share grew.
        Assert.True(RiskScorer.EffectiveMaxima(lib)[RiskCategoryNames.Cve] > cveBefore);
    }

    [Fact]
    public void A_library_is_not_marked_down_for_missing_iac_or_dast_scanners()
    {
        var lib = Policy();
        ArchetypeScoring.ApplyCapability(lib, Library);

        var ms = lib.Categories[RiskCategoryNames.MissingScanners].Weights;
        Assert.Equal(0, ms["iac"]);
        Assert.Equal(0, ms["dast"]);
        Assert.Equal(1, ms["sast"]);   // source-capable, still expected
    }

    [Fact]
    public void A_service_keeps_every_category()
    {
        var svc = Policy();
        ArchetypeScoring.ApplyCapability(svc, Service);

        Assert.True(svc.Categories[RiskCategoryNames.IacSevere].Enabled);
        Assert.Equal(1, svc.Categories[RiskCategoryNames.MissingScanners].Weights["iac"]);
    }
}
