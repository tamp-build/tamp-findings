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

    // The shipped STARTER control mapping (ADR 0009 §4). A control maps to the
    // gates that would cover it — but an assertion is only emitted for the gates a
    // template actually enables, so no template claims coverage it does not have.
    // The remainder ship Unmapped on purpose: the no-unmapped meta-gate then reports
    // the real, honest gap rather than a fabricated 100%. Filling the matrix is
    // ongoing compliance work, not a code change.
    private static readonly (string Control, string[] Gates)[] StarterGatedMap =
    [
        ("RA-5", [GateKeys.KevExposure, GateKeys.CriticalCves, GateKeys.HighCves, GateKeys.SbomAge]), // vuln scanning
        ("SI-2", [GateKeys.KevExposure, GateKeys.CriticalCves, GateKeys.PoamPastDue]),                // flaw remediation
        ("CM-8", [GateKeys.SbomAge]),                                                                 // component inventory
        ("SR-3", [GateKeys.SbomAge, GateKeys.DeniedLicenses]),                                        // supply chain
        ("IA-5", [GateKeys.VerifiedSecrets]),                                                         // authenticator mgmt
        ("SA-11", [GateKeys.CriticalSast, GateKeys.HighSast, GateKeys.CoverageFloor]),                // developer testing
        ("SA-15", [GateKeys.CriticalSast, GateKeys.CoverageFloor]),                                   // dev process/tools
        ("SI-10", [GateKeys.CriticalDast]),                                                           // input validation (web)
        ("SC-7",  [GateKeys.CriticalDast]),                                                           // boundary protection (web)
        ("CA-8",  [GateKeys.CriticalDast]),                                                           // penetration testing (web)
        ("CM-6",  [GateKeys.CriticalIac]),                                                            // config settings (iac)
        ("CM-7",  [GateKeys.CriticalIac]),                                                            // least functionality (iac)
    ];

    // Enable the no-unmapped meta-gate and attach the starter assertions the
    // template's OWN enabled gates support. Applied to the federal baselines; Tamp
    // Standard ships neither (it is the permissive OSS default, not a compliance
    // posture).
    private static PolicyLayer WithCoverageMapping(PolicyLayer layer)
    {
        var enabled = layer.Gates.Where(g => g.Value.Enabled).Select(g => g.Key).ToHashSet(StringComparer.Ordinal);
        foreach (var (control, gates) in StarterGatedMap)
        {
            var applicable = gates.Where(enabled.Contains).ToList();
            if (applicable.Count > 0)
                layer.Assertions.Add(new ControlAssertion
                {
                    Kind = ControlDispositionKind.Gated,
                    ControlIds = [control],
                    Gates = applicable,
                });
        }

        // Physical/environmental protection is the platform's, not the app's — a
        // representative inherited claim so the model ships all four dispositions.
        layer.Assertions.Add(new ControlAssertion
        {
            Kind = ControlDispositionKind.Inherited,
            ControlIds = ["PE-2", "PE-3", "PE-6"],
            InheritedFrom = "the hosting provider's authorized boundary (IaaS)",
            Justification = "physical and environmental protection is provided by the underlying platform",
        });

        // The meta-gate itself: enabled so coverage is measured; blocking is the
        // enforcement lever (ADR 0004) — advisory until the matrix is clean.
        layer.Gates[GateKeys.NoUnmapped] = On();
        return layer;
    }

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
    public static PolicyLayer BuildFedRampLow() => WithCoverageMapping(new()
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
    });

    /// <summary>FedRAMP Moderate: Low + critical SAST.</summary>
    public static PolicyLayer BuildFedRampModerate() => WithCoverageMapping(new()
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
    });

    /// <summary>FedRAMP High: the strictest floor — high CVE/SAST, critical DAST
    /// and IaC, base-image age and POA&amp;M past-due all bite (the conditional
    /// ones apply only where the component's capability produces them, 181b/c).</summary>
    public static PolicyLayer BuildFedRampHigh() => WithCoverageMapping(new()
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
    });

    /// <summary>GovRAMP Core: enforcing, no DAST in the required set (state/local
    /// verification), KEV / critical CVE / critical SAST / verified secrets.</summary>
    public static PolicyLayer BuildGovRampCore() => WithCoverageMapping(new()
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
    });
}
