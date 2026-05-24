using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Domain.Risk;

// Single source of truth for the v1 "Tamp Standard" policy. The
// migration seeds a RiskPolicy row from this builder; the unit-test
// fixture uses it as a known-good baseline.
public static class RiskPolicyDefaults
{
    public const string TampStandardV1Name = "Tamp Standard v1";

    public static RiskPolicyConfig BuildTampStandardV1() => new()
    {
        SchemaVersion = 1,
        Bands = new RiskBands { GreenMax = 10, YellowMax = 25, OrangeMax = 50 },
        Categories = new()
        {
            [RiskCategoryNames.Cve] = new()
            {
                Enabled = true, Max = 25,
                Weights = new() { ["critical"] = 0.50, ["high"] = 0.25, ["medium"] = 0.05, ["low"] = 0.01 },
            },
            [RiskCategoryNames.Secrets] = new()
            {
                Enabled = true, Max = 15,
                Weights = new() { ["verified"] = 1.00, ["unverified"] = 0.10 },
            },
            [RiskCategoryNames.SastSevere] = new()
            {
                Enabled = true, Max = 15,
                Weights = new() { ["critical"] = 0.50, ["high"] = 0.20 },
            },
            [RiskCategoryNames.IacSevere] = new()
            {
                Enabled = true, Max = 10,
                Weights = new() { ["critical"] = 0.50, ["high"] = 0.20 },
            },
            [RiskCategoryNames.Coverage] = new()
            {
                Enabled = true, Max = 10,
                Weights = new() { ["targetPercent"] = 80, ["unmeasuredScore"] = 1.0 },
            },
            [RiskCategoryNames.SbomStaleness] = new()
            {
                Enabled = true, Max = 10,
                Weights = new() { ["outdated"] = 0.5, ["stale"] = 2.0 },
            },
            [RiskCategoryNames.Tests] = new()
            {
                Enabled = true, Max = 5,
                Weights = new() { ["failureMultiplier"] = 5, ["anyFailureFloor"] = 0.1, ["unmeasuredScore"] = 0.5 },
            },
            [RiskCategoryNames.License] = new()
            {
                Enabled = true, Max = 5,
                Weights = new() { ["denied"] = 0.5, ["strongCopyleft"] = 0.1, ["unknownPctMul"] = 0.2 },
            },
            [RiskCategoryNames.SastLow] = new()
            {
                Enabled = true, Max = 3,
                Weights = new() { ["medium"] = 0.002, ["low"] = 0.0005 },
            },
            [RiskCategoryNames.MissingScanners] = new()
            {
                Enabled = true, Max = 2,
                Weights = new(),
            },
        },
    };
}
