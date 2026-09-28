using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Domain.Risk;

/// <summary>
/// The system-seeded policy templates (ADR 0007 / TFND-182). The shipped
/// strictness ladder: Tamp Standard &lt; FedRAMP Low &lt; Moderate &lt; High,
/// plus GovRAMP Core as its own floor. Kept beside <see cref="RiskPolicyDefaults"/>
/// so the shipped baselines live in one place; seeded idempotently by name at
/// startup. A template links a scoring RiskPolicy (Tamp Standard for the
/// advisory baseline, Tamp Federal for the enforcing ones) and layers the
/// blocking policy on top.
///
/// Gate values follow the templates brief §7. Two value calls the owner can tune
/// (TFND-182): the coverage floor (70% on the enforcing baselines) and the SBOM
/// max-age (14 days enforcing, 30 advisory on Standard).
/// </summary>
public static class PolicyTemplateDefaults
{
    public const string TampStandardName = "Tamp Standard";
    public const string FedRampLowName = "FedRAMP Low";
    public const string FedRampModerateName = "FedRAMP Moderate";
    public const string FedRampHighName = "FedRAMP High";
    public const string GovRampCoreName = "GovRAMP Core";

    // Scanner-class identifiers (match the v3 handoff SCANNER_CLASSES / the six).
    public static class ScannerClasses
    {
        public const string StaticAnalysis = "Static analysis";
        public const string DynamicScan = "Dynamic scan";
        public const string Secrets = "Secrets";
        public const string Iac = "IaC misconfig";
        public const string Sbom = "SBOM";
        public const string Coverage = "Coverage";
    }

    // Federal POA&M windows (risk-based, identical across FedRAMP/GovRAMP baselines).
    private static Dictionary<string, int> FederalPoam() =>
        new() { ["Critical"] = 30, ["High"] = 30, ["Medium"] = 90, ["Low"] = 180 };

    private static GateConfig On(double? threshold = null) => new() { Enabled = true, Threshold = threshold };

    private static readonly string[] AllSix =
    [
        ScannerClasses.StaticAnalysis, ScannerClasses.DynamicScan, ScannerClasses.Secrets,
        ScannerClasses.Iac, ScannerClasses.Sbom, ScannerClasses.Coverage,
    ];

    /// <summary>The permissive OSS-safe default: advisory, a sensible scanner
    /// floor, KEV + verified-secrets + SBOM-age reported (not blocking), no
    /// coverage floor (collected, not gated).</summary>
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
            [GateKeys.KevExposure] = On(0),
            [GateKeys.VerifiedSecrets] = On(0),
            [GateKeys.SbomAge] = On(30),   // advisory via the template mode
        },
    };

    /// <summary>FedRAMP Low: enforcing, all six scanners, the KEV / critical-CVE /
    /// verified-secrets floor, SBOM-age and a coverage floor.</summary>
    public static PolicyLayer BuildFedRampLow() => new()
    {
        Mode = EnforcementMode.Enforcing,
        RequiredScanners = { AllSix[0], AllSix[1], AllSix[2], AllSix[3], AllSix[4], AllSix[5] },
        DeniedLicenses = { "AGPL-*", "SSPL-1.0" },
        PoamDeadlineDays = FederalPoam(),
        Gates =
        {
            [GateKeys.KevExposure] = On(0),
            [GateKeys.CriticalCves] = On(0),
            [GateKeys.VerifiedSecrets] = On(0),
            [GateKeys.SbomAge] = On(14),
            [GateKeys.CoverageFloor] = On(70),
        },
    };

    /// <summary>FedRAMP Moderate: Low + critical SAST.</summary>
    public static PolicyLayer BuildFedRampModerate() => new()
    {
        Mode = EnforcementMode.Enforcing,
        RequiredScanners = { AllSix[0], AllSix[1], AllSix[2], AllSix[3], AllSix[4], AllSix[5] },
        DeniedLicenses = { "AGPL-*", "SSPL-1.0" },
        PoamDeadlineDays = FederalPoam(),
        Gates =
        {
            [GateKeys.KevExposure] = On(0),
            [GateKeys.CriticalCves] = On(0),
            [GateKeys.CriticalSast] = On(0),
            [GateKeys.VerifiedSecrets] = On(0),
            [GateKeys.SbomAge] = On(14),
            [GateKeys.CoverageFloor] = On(70),
        },
    };

    /// <summary>FedRAMP High: the strictest floor — high CVE/SAST, critical DAST
    /// and IaC, base-image age and POA&amp;M past-due all bite (the conditional
    /// ones apply only where the component's capability produces them, 181b/c).</summary>
    public static PolicyLayer BuildFedRampHigh() => new()
    {
        Mode = EnforcementMode.Enforcing,
        RequiredScanners = { AllSix[0], AllSix[1], AllSix[2], AllSix[3], AllSix[4], AllSix[5] },
        DeniedLicenses = { "AGPL-*", "SSPL-1.0" },
        PoamDeadlineDays = FederalPoam(),
        Gates =
        {
            [GateKeys.KevExposure] = On(0),
            [GateKeys.CriticalCves] = On(0),
            [GateKeys.HighCves] = On(0),
            [GateKeys.CriticalSast] = On(0),
            [GateKeys.HighSast] = On(0),
            [GateKeys.CriticalDast] = On(0),
            [GateKeys.CriticalIac] = On(0),
            [GateKeys.VerifiedSecrets] = On(0),
            [GateKeys.BaseImageAge] = On(90),
            [GateKeys.PoamPastDue] = On(0),
            [GateKeys.SbomAge] = On(14),
            [GateKeys.CoverageFloor] = On(70),
        },
    };

    /// <summary>GovRAMP Core: enforcing, no DAST in the required set (state/local
    /// verification), KEV / critical CVE / critical SAST / verified secrets.</summary>
    public static PolicyLayer BuildGovRampCore() => new()
    {
        Mode = EnforcementMode.Enforcing,
        RequiredScanners =
        {
            ScannerClasses.StaticAnalysis, ScannerClasses.Secrets,
            ScannerClasses.Iac, ScannerClasses.Sbom, ScannerClasses.Coverage,
        },
        DeniedLicenses = { "AGPL-*" },
        PoamDeadlineDays = FederalPoam(),
        Gates =
        {
            [GateKeys.KevExposure] = On(0),
            [GateKeys.CriticalCves] = On(0),
            [GateKeys.CriticalSast] = On(0),
            [GateKeys.VerifiedSecrets] = On(0),
            [GateKeys.SbomAge] = On(14),
            [GateKeys.CoverageFloor] = On(70),
        },
    };
}
