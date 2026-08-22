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

    public const string TampFederalV1Name = "Tamp Federal v1";

    // SchemaVersion 2 policy for contract work that specifies dynamic
    // analysis alongside static (SSDF PW.8.1 / 800-53 SA-11(8)).
    //
    // Weights are relative, not a 100-point budget — the scorer normalises
    // against the enabled basis (114 here), so adding the two dast
    // categories didn't require taking points off cve/sast/coverage the
    // way a v1 policy would have. Effective maxima land at roughly:
    //   cve 21.9 · secrets 13.2 · sastSevere 13.2 · dastSevere 10.5
    //   iacSevere 8.8 · coverage 8.8 · sbomStaleness 8.8 · tests 4.4
    //   license 4.4 · sastLow 2.6 · missingScanners 1.8 · dastLow 1.8
    //
    // dastSevere uses the same 0.50 critical weight as sastSevere: a
    // runtime-confirmed finding shouldn't score softer than a static
    // pattern match against the same weakness.
    //
    // Not marked IsDefault — projects opt in via Project.RiskPolicyId so
    // adopting this never rescores anyone else's work.
    public static RiskPolicyConfig BuildTampFederalV1() => new()
    {
        SchemaVersion = 2,
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
            [RiskCategoryNames.DastSevere] = new()
            {
                Enabled = true, Max = 12,
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
                // Explicit expectations — federal work is expected to run
                // all six classes, DAST included. A component with no
                // deployed surface should clear dast to 0 on its own
                // project-scoped clone rather than carry a permanent ding.
                Weights = new()
                {
                    [ExpectedScannerKeys.Sast] = 1,
                    [ExpectedScannerKeys.Secrets] = 1,
                    [ExpectedScannerKeys.Iac] = 1,
                    [ExpectedScannerKeys.Sbom] = 1,
                    [ExpectedScannerKeys.Coverage] = 1,
                    [ExpectedScannerKeys.Dast] = 1,
                },
            },
            [RiskCategoryNames.DastLow] = new()
            {
                Enabled = true, Max = 2,
                Weights = new() { ["medium"] = 0.002, ["low"] = 0.0005 },
            },
        },
    };
}
