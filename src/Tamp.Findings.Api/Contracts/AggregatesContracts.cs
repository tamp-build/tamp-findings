namespace Tamp.Findings.Api.Contracts;

// Single-shot summary for the hierarchy ring view. Calling without
// filters returns an org-wide aggregate; with a tier filter (one of
// clientId / projectId / componentId) the aggregate scopes to that
// subtree. Uses sum aggregation per F1.2 — never worst-case.
public sealed record AggregatesResponse(
    AggregateScope Scope,
    FindingAggregate Findings,
    SbomAggregate Sbom,
    SecretsAggregate Secrets);

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
    IReadOnlyList<ScannerDetail> ByScannerDetail);

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
    int Vulnerable); // red: has any Vulnerability row
