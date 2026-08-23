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
            // NO quality category here, deliberately (TFND-33 … TFND-37).
            //
            // This is a SchemaVersion 1 policy: Max is absolute points out of a
            // fixed 100-point budget, and these weights already sum to exactly
            // 100. Adding a category would either push the total past 100 —
            // where the scorer's clamp makes effective maxima stop matching
            // authored ones — or require taking points off cve, sast or
            // coverage, which would silently rescore every project on the
            // seeded policy.
            //
            // Neither is acceptable as a side effect of wiring five scanners.
            // The federal v2 policy below carries the category, because
            // relative weights REDISTRIBUTE rather than overflow; an admin who
            // wants it on a v1 policy adds it in the editor, which shows
            // exactly how the other ceilings move.
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
                    // TFND-27. A UI-facing federal deliverable must conform to
                    // Section 508; a headless service clones this policy and
                    // zeroes the key rather than carrying a permanent ding.
                    [ExpectedScannerKeys.Accessibility] = 1,
                },
            },
            [RiskCategoryNames.DastLow] = new()
            {
                Enabled = true, Max = 2,
                Weights = new() { ["medium"] = 0.002, ["low"] = 0.0005 },
            },
            // TFND-33 … TFND-37 — OpenAPI lint, breaking-change detection,
            // mutation testing, architecture rules.
            //
            // ENABLED with a deliberately small weight. Enabled because a
            // scanner whose findings score nothing is a scanner nobody looks
            // at, and this repo already runs several of them. Small because
            // none of these tools finds something that should stop a release:
            // they find work, not danger, and weighting them like a CVE would
            // teach people that the number is noise.
            [RiskCategoryNames.Quality] = new()
            {
                Enabled = true, Max = 2,
                Weights = new() { ["high"] = 0.01, ["medium"] = 0.004, ["low"] = 0.001 },
            },
            // TFND-27 — Section 508 / WCAG 2.1 AA.
            //
            // Weighted like iacSevere rather than like the quality category:
            // for federal work an inaccessible control blocks acceptance, and
            // scoring it as a nit would misrepresent what it costs. A severe
            // axe violation is a control somebody cannot operate at all.
            [RiskCategoryNames.Accessibility] = new()
            {
                Enabled = true, Max = 8,
                Weights = new() { ["severe"] = 0.20, ["moderate"] = 0.02, ["minor"] = 0.004 },
            },
        },
    };
}
