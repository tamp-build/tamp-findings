using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Api.Contracts;

// Normalized SBOM ingest payload. The build orchestrator parses native
// CycloneDX (or any tool's SBOM output) into this shape before POSTing.
// Keeping the wire contract independent of CycloneDX-specific fields
// lets us evolve the canonical shape without breaking ingest clients.
public sealed record SbomIngestRequest(
    // Build context — same address-by-name pattern as IngestRequest.
    string Client,
    string Project,
    string Component,
    string? ComponentKind,
    string? Flavor,
    string Version,
    string? CommitSha,
    string? Branch,
    string? BuildId,
    string? PullRequestRef,
    // SBOM provenance
    string? SerialNumber,
    string? SpecVersion,
    string? ToolName,
    string? ToolVersion,
    // Graph
    IReadOnlyList<SbomComponentDto> Components,
    IReadOnlyList<SbomDependencyDto> Dependencies,
    // TFND-21: CycloneDX metadata.tools captured verbatim as a list of
    // property bags (vendor, name, version, …). Null means "not provided".
    IReadOnlyList<Dictionary<string, string?>>? MetadataTools = null);

public sealed record SbomComponentDto(
    string Purl,
    string Name,
    string Version,
    string? Kind,
    string? License,
    IReadOnlyList<VulnerabilityDto> Vulnerabilities,
    // TFND-21: algorithm → hash value map (SHA-256, SHA-1, …).
    IReadOnlyDictionary<string, string>? Hashes = null);

public sealed record VulnerabilityDto(
    string AdvisoryId,
    Severity Severity,
    string? Title,
    string? Description,
    string? FixedInVersion,
    string? ReferenceUrl,
    ScannerKind Source,
    // Optional so scanners that report a severity band and nothing else can
    // keep posting the same payload they always have.
    double? CvssScore = null,
    string? CvssVector = null);

public sealed record SbomDependencyDto(
    string ParentPurl,
    string ChildPurl);

public sealed record SbomIngestResponse(
    Guid ComponentVersionId,
    Guid SbomSnapshotId,
    int ComponentsCount,
    int DependenciesCount,
    int VulnerabilitiesCount);
