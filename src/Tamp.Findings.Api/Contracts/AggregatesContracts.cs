using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Api.Contracts;

// Single-shot summary for the hierarchy ring view. Calling without
// filters returns an org-wide aggregate; with a tier filter (one of
// clientId / projectId / componentId) the aggregate scopes to that
// subtree. Uses sum aggregation per F1.2 — never worst-case.
public sealed record AggregatesResponse(
    AggregateScope Scope,
    FindingAggregate Findings,
    SbomAggregate Sbom,
    SecretsAggregate Secrets,
    LicensesAggregate Licenses,
    IacAggregate Iac,
    CoverageAggregate Coverage,
    // One entry per scanner that's run against any latest CV in scope.
    // Empty means no scanners have reported in. Used by the SPA to render
    // "scanned · clean" (green) vs "never ran" (grey) on rings whose finding
    // count is zero — TFND-15.
    IReadOnlyList<ScanRunSummaryDto> ScanRuns,
    // Risk Assessment Policy score for this scope. Null when there's no
    // ingest evidence (brand-new client with no scans/SBOM/coverage), so
    // the SPA can render "not yet scored" instead of a misleading 0%.
    RiskScoreDto? Risk);

public sealed record RiskScoreDto(
    double Score,             // 0..100
    string Band,              // "green" | "yellow" | "orange" | "red"
    Guid PolicyId,
    string PolicyName,
    int SchemaVersion,
    IReadOnlyList<RiskBreakdownDto> Breakdown);

public sealed record RiskBreakdownDto(
    string Key, bool Enabled,
    // Weight as authored in the policy. Absolute points under schema 1,
    // a relative weight under schema 2.
    double Max,
    // Points the category can cost at full saturation once normalised
    // against the enabled weight basis. Equals Max for a well-formed
    // schema-1 policy. This is the figure the policy editor should show.
    double EffectiveMax,
    double SubScore, double Contribution);

// Secrets ring (innermost concentric) — verified credentials are the
// closest thing we can render to "actively exploitable right now".
// Buckets sourced from open TruffleHog findings: Critical = Verified
// (the credential authenticated against the live service), High =
// Unverified (pattern matched but TruffleHog skipped or failed the
// verification probe). Other severities are ignored. Trivy's secret
// subcategory could fold in here later once we track rule categories.
public sealed record SecretsAggregate(SecretsHealthCounts Health);

public sealed record SecretsHealthCounts(
    int Verified,     // red — TruffleHog reported a live credential
    int Unverified);  // yellow — pattern match, no verification

// Innermost ring — license posture. Tiers go from most permissive
// (lightest green) to least permissive / outright denied (red), with a
// neutral "unknown" bucket for the small slice we couldn't categorize
// either from the SBOM or from registry enrichment. The ByLicense map
// powers the table-of-percentages on the right of the donut.
public sealed record LicensesAggregate(
    LicenseTierCounts Tiers,
    IReadOnlyDictionary<string, int> ByLicense);

public sealed record LicenseTierCounts(
    int Permissive,      // MIT, Apache-2.0, BSD-*, ISC, 0BSD, MPL-2.0 etc.
    int WeakCopyleft,    // LGPL-2.1, EPL — file-level / library-level copyleft
    int StrongCopyleft,  // GPL-2.0, LGPL-3.0 — affects derivatives
    int Denied,          // GPL-3.0, AGPL, SSPL — release-blocking by default
    int Unknown);        // missing license or unrecognized expression

public sealed record AggregateScope(
    string? ClientName,
    string? ProjectName,
    string? ComponentName,
    // Self-describing label for the ring center: "All" / "BrewingCoder" /
    // "BrewingCoder / Tamp" / "BrewingCoder / Tamp / tamp.findings".
    string Label,
    string Level);     // "All" | "Client" | "Project" | "Component"

public sealed record FindingAggregate(
    SeverityCounts Counts,
    IReadOnlyDictionary<string, int> ByScanner,
    IReadOnlyDictionary<string, int> ByStatus,
    // Per-scanner detail for the segmented ring view. Counts split by
    // severity (open only) plus separate closed/suppressed/accepted
    // buckets — enough to render a donut where every finding ever seen
    // for the scanner has a slot. Always returns every scanner the user
    // currently has data for, sorted alphabetically; the SPA decides
    // which one to render as the outer ring.
    IReadOnlyList<ScannerDetail> ByScannerDetail,
    // TFND-18: Top-N rules by count. Powers the "Top rules" table on
    // Overview and the rule-drill from there into FindingsView.
    IReadOnlyList<FindingRuleSummaryDto> ByRule);

public sealed record FindingRuleSummaryDto(
    string RuleId,
    int Count,
    Severity Severity,
    ScannerKind Scanner);

public sealed record ScannerDetail(
    string Scanner,
    SeverityCounts Open,
    int Closed,
    int Suppressed,
    int Accepted)
{
    public int Total => Open.Total + Closed + Suppressed + Accepted;
}

public sealed record SbomAggregate(
    int ComponentsCount,
    int VulnerabilitiesCount,
    IReadOnlyDictionary<string, int> ByEcosystem,
    // F6.4 health rollup driving the SBOM ring on the Overview tab.
    // Priority is Vulnerable > Outdated > Current — a component with both
    // a known CVE and a newer version available counts as Vulnerable.
    // Yellow (Outdated) requires LatestVersion to be populated by an
    // enrichment pass that doesn't exist yet, so today every non-vuln
    // dep falls into Current. When registry enrichment lands the same
    // payload shape carries the new signal automatically.
    SbomHealthCounts Health);

public sealed record SbomHealthCounts(
    int Current,     // green: no vuln + (no LatestVersion OR LatestVersion == Version)
    int Outdated,    // yellow: no vuln + LatestVersion populated and != Version
    int Vulnerable,  // red: has any Vulnerability row
    // TFND-22: sub-count of Outdated where LatestReleasedAt > 180 days ago.
    // Lets the SPA highlight components that have been outdated for a long
    // time vs. ones that dropped behind in the last few weeks.
    int Stale);

// Bullseye — IaC / container misconfig from Trivy. Bucketed by severity
// like the outer Code Quality ring. `Scanned` distinguishes "we ran
// Trivy and found nothing" (green) from "Trivy has no signal in scope
// at all" (grey). Today the proxy is "any Trivy finding ever ingested
// in scope" — when we add per-build scan-invocation receipts this
// becomes more honest. tamp.findings has no IaC files so the bullseye
// renders grey here.
public sealed record IacAggregate(
    SeverityCounts Counts,
    bool Scanned);

// Outermost ring — line coverage. `Measured` is the equivalent of
// IacAggregate.Scanned: false means no CoverageReport exists in scope
// (render grey). When measured, SequenceCoverage drives the tier color
// and the ring is split into a covered-percent slice (tier color) plus
// an uncovered-percent slice (light grey).
public sealed record CoverageAggregate(
    bool Measured,
    double? SequenceCoverage,
    double? BranchCoverage,
    int CoveredSequences,
    int TotalSequences,
    IReadOnlyList<CoverageModuleSummary> Modules);

public sealed record CoverageModuleSummary(
    string Name,
    double SequenceCoverage,
    int CoveredSequences,
    int TotalSequences);
