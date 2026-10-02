using Tamp.Findings.Domain.Values;

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

    // Effective enforcement mode override for this project (TFND-148). Null →
    // inherit (Client → Instance). Orthogonal to the per-gate enable flags:
    // enabling a gate and enforcing on it are two different switches, and the
    // adoption path is to enable gates in advisory first, then flip to enforcing.
    public EnforcementMode? EnforcementMode { get; set; }
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
    // Any critical DAST finding (canonical scope). Distinct from criticalSast
    // because a runtime-confirmed exploit path is categorically stronger
    // evidence than a static pattern match against the same weakness — a
    // project may reasonably gate on one and not the other.
    public const string CriticalDast = "criticalDast";

    // High-severity SAST / DAST. These exist because SARIF's level vocabulary
    // is only error | warning | note | none — there is no "critical". A
    // scanner that reports through SARIF levels alone therefore tops out at
    // High, and criticalSast / criticalDast can never fire for it. That was
    // true of every SAST scanner in the pipeline and of ZAP: a confirmed SQL
    // injection arrived as High and sailed through a "critical" gate.
    //
    // Critical is still reachable — findings whose rule carries a
    // security-severity (CVSS) property are banded from it, and CVEs and
    // verified secrets have always had real Critical severities. But for the
    // scanners that don't report one, these are the gates that actually bite.
    public const string HighSast = "highSast";
    public const string HighDast = "highDast";
    // Any verified secret (TruffleHog verified bucket).
    public const string VerifiedSecrets = "verifiedSecrets";
    // Any denied-license component.
    public const string DeniedLicenses = "deniedLicenses";

    // TFND-134. How old the base image was when the build ran, in days.
    public const string BaseImageAge = "baseImageAge";
    // Any failed test in the latest TestRunReport.
    public const string TestFailures = "testFailures";
    // Coverage dropped from prior canonical build by more than Threshold
    // percentage points.
    public const string CoverageRegression = "coverageRegression";
    // Coverage is below an ABSOLUTE floor (Threshold %). Distinct from
    // coverageRegression (relative, vs prior): "produce a number, any number
    // passes" is not a gate (TFND-182). Threshold is the minimum percent.
    public const string CoverageFloor = "coverageFloor";
    // How old the build's SBOM is, in days (the snapshot's own age, distinct
    // from base-image age and from component-version staleness). Under continuous
    // validation, stale evidence is no evidence (TFND-182). Threshold is the max
    // days allowed.
    public const string SbomAge = "sbomAge";
    // Any open POA&M whose scheduled completion date is more than
    // `Threshold` days past due. Counts items in Open / InProgress
    // statuses; Completed / RiskAccepted / Cancelled do not. FedRAMP
    // continuous monitoring expects past-due items to be flagged
    // explicitly so the AO can decide whether to extend or escalate.
    // Threshold default 0 (any day past due fails).
    public const string PoamPastDue = "poamPastDue";

    // Code-quality process gates (TFND-175). The quality SCORE is finding magnitude;
    // these are the pass/fail process half of the ship decision.
    // A SonarQube-style quality-gate verdict: FAIL blocks; no verdict reads Unknown.
    public const string QualityGate = "qualityGate";
    // Analysis-coverage completeness: a language above a footprint threshold left
    // unanalyzed blocks — so "0 findings" only credits SA-11 when coverage is real.
    public const string AnalysisCoverage = "analysisCoverage";

    // Control posture checks (TFND-212) — boolean gates fed by producer-reported
    // repo/org settings. A required posture gate with no observation reads Unknown
    // (blocks), same "unscanned is not clean" rule as the scanner gates. Each maps
    // to the change-control / authentication controls it provides evidence for, so
    // a passing check moves those controls off the stopgap "Inherited" disposition.
    public const string BranchProtection = "branchProtection";
    public const string PrReviewsRequired = "prReviewsRequired";
    public const string SignedCommits = "signedCommits";
    public const string OrgTwoFactor = "orgTwoFactor";
    public const string Codeowners = "codeowners";

    // TFND-185 / ADR 0009 — the "no-unmapped" META-gate. Unlike every other gate
    // it reads no scanner count; it reads the control-disposition set and blocks
    // when any in-scope control has no disposition (gated / inherited / N/A).
    // It gates the coverage of the MAPPING itself. Unanswerable (Unknown) when no
    // framework is assigned or no catalog is loaded — a gate that claims to cover
    // controls with no controls to check is a misconfiguration, not a clean build.
    public const string NoUnmapped = "noUnmapped";

    // TFND-191 / ADR 0006 — the review-gated ADR-conformance gate. Turns
    // ADR-conformance evidence into a go/no-go, but human-first: a conformance
    // finding blocks ONLY when it is undispositioned, its RULE is Reviewed (Draft
    // rules never block), and a Semantic verdict is verify-Confirmed. Rides the
    // advisory<enforcing machinery (ADR 0004) — no new enforcement mechanism.
    public const string AdrConformance = "adrConformance";
}

public static class ProjectGatesDefaults
{
    // Conservative default: nothing enabled. Admins opt in per gate.
    public static ProjectGatesConfig Empty() => new();
}
