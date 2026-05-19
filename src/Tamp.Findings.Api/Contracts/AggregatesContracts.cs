namespace Tamp.Findings.Api.Contracts;

// Single-shot summary for the hierarchy ring view. Calling without
// filters returns an org-wide aggregate; with a tier filter (one of
// clientId / projectId / componentId) the aggregate scopes to that
// subtree. Uses sum aggregation per F1.2 — never worst-case.
public sealed record AggregatesResponse(
    AggregateScope Scope,
    FindingAggregate Findings,
    SbomAggregate Sbom);

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
    IReadOnlyDictionary<string, int> ByEcosystem);
