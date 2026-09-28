using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Domain.Risk;

/// <summary>
/// The system-seeded policy templates (ADR 0007). Kept beside
/// <see cref="RiskPolicyDefaults"/> so the shipped baselines live in one place.
/// Seeded idempotently by name at startup; a template links a scoring
/// <see cref="Entities.RiskPolicy"/> for weights/bands and layers the blocking
/// policy on top.
/// </summary>
public static class PolicyTemplateDefaults
{
    public const string TampStandardName = "Tamp Standard";
    public const string FedRampModerateName = "FedRAMP Moderate";

    // Scanner-class identifiers used across the policy layers (match the v3
    // handoff's SCANNER_CLASSES).
    public static class ScannerClasses
    {
        public const string StaticAnalysis = "Static analysis";
        public const string DynamicScan = "Dynamic scan";
        public const string Secrets = "Secrets";
        public const string Iac = "IaC misconfig";
        public const string Sbom = "SBOM";
        public const string Coverage = "Coverage";
    }

    /// <summary>The permissive baseline: advisory, a sensible scanner floor, a
    /// single obviously-incompatible licence denied, standard POA&amp;M windows.</summary>
    public static PolicyLayer BuildTampStandard() => new()
    {
        Mode = EnforcementMode.Advisory,
        RequiredScanners =
        {
            ScannerClasses.StaticAnalysis, ScannerClasses.Secrets,
            ScannerClasses.Sbom, ScannerClasses.Coverage,
        },
        DeniedLicenses = { "SSPL-1.0" },
        PoamDeadlineDays = { ["Critical"] = 30, ["High"] = 90, ["Medium"] = 180, ["Low"] = 365 },
        Gates =
        {
            [GateKeys.KevExposure] = new GateConfig { Enabled = true, Threshold = 0 },
        },
    };

    /// <summary>The federal baseline: enforcing, all six scanner classes, a
    /// stronger deny-list, tighter POA&amp;M windows, and the KEV / critical gates on.</summary>
    public static PolicyLayer BuildFedRampModerate() => new()
    {
        Mode = EnforcementMode.Enforcing,
        RequiredScanners =
        {
            ScannerClasses.StaticAnalysis, ScannerClasses.DynamicScan, ScannerClasses.Secrets,
            ScannerClasses.Iac, ScannerClasses.Sbom, ScannerClasses.Coverage,
        },
        DeniedLicenses = { "AGPL-*", "SSPL-1.0" },
        PoamDeadlineDays = { ["Critical"] = 30, ["High"] = 30, ["Medium"] = 90, ["Low"] = 180 },
        Gates =
        {
            [GateKeys.KevExposure] = new GateConfig { Enabled = true, Threshold = 0 },
            [GateKeys.CriticalCves] = new GateConfig { Enabled = true, Threshold = 0 },
            [GateKeys.CriticalSast] = new GateConfig { Enabled = true, Threshold = 0 },
            [GateKeys.VerifiedSecrets] = new GateConfig { Enabled = true, Threshold = 0 },
        },
    };
}
