namespace Tamp.Findings.Domain.Risk;

// Project-scoped acceptance gates. Distinct from RiskPolicy (which
// drives the score) — gates are pass/fail blockers evaluated against
// a specific build. A failing gate means "don't merge this", not
// "your overall risk went up by X%".
//
// Stored as jsonb on Project.GatesConfig. SchemaVersion lets future
// gate shapes migrate forward; evaluators fail fast on unknown
// versions.
public sealed class ProjectGatesConfig
{
    public int SchemaVersion { get; set; } = 1;
    // Per-gate config. Gate keys are well-known (see GateKeys); unknown
    // keys are ignored by the evaluator so adding a new gate type
    // doesn't break old deployments.
    public Dictionary<string, GateConfig> Gates { get; set; } = new();
}

public sealed class GateConfig
{
    public bool Enabled { get; set; }
    // Used by threshold-based gates (e.g. "coverage dropped > Threshold%"
    // or "risk score increased > Threshold points"). Ignored by
    // boolean gates.
    public double? Threshold { get; set; }
}

public static class GateKeys
{
    // Score regression — fail when this build's score > prior canonical
    // build's score by more than Threshold points (Threshold 0 = "any
    // regression at all"). Defaults to 0.
    public const string RiskScoreRegression = "riskScoreRegression";
    // Any open CVE in the SBOM, regardless of severity.
    public const string AnyCves = "anyCves";
    public const string CriticalCves = "criticalCves";
    public const string HighCves = "highCves";
    // Any open CVE on the CISA Known Exploited Vulnerabilities catalog
    // (M-22-09 / BOD 22-01). Treat as its own gate because KEV listing
    // is a categorical "actively exploited" signal, distinct from CVSS
    // severity. Federal acceptance expects zero exposure.
    public const string KevExposure = "kevExposure";
    // Any critical SAST finding (canonical scope).
    public const string CriticalSast = "criticalSast";
    public const string CriticalIac = "criticalIac";
    // Any verified secret (TruffleHog verified bucket).
    public const string VerifiedSecrets = "verifiedSecrets";
    // Any denied-license component.
    public const string DeniedLicenses = "deniedLicenses";
    // Any failed test in the latest TestRunReport.
    public const string TestFailures = "testFailures";
    // Coverage dropped from prior canonical build by more than Threshold
    // percentage points.
    public const string CoverageRegression = "coverageRegression";
}

public static class ProjectGatesDefaults
{
    // Conservative default: nothing enabled. Admins opt in per gate.
    public static ProjectGatesConfig Empty() => new();
}
