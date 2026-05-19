using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Build.Adapters;

// Wire-shape DTOs that exactly mirror the API's IngestRequest /
// SbomIngestRequest. Duplicated rather than sharing the API project's
// types because the build orchestrator deliberately has no reference to
// the API runtime; only the wire contract matters. If the contract ever
// drifts, integration tests will catch it.
public sealed record IngestRequestDto(
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
    ScannerKind Scanner,
    IReadOnlyList<IngestFindingDto> Findings);

public sealed record IngestFindingDto(
    string RuleId,
    Severity Severity,
    string Title,
    string? Description,
    string? FilePath,
    int? Line,
    string? Snippet);

public sealed record SbomIngestRequestDto(
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
    string? SerialNumber,
    string? SpecVersion,
    string? ToolName,
    string? ToolVersion,
    IReadOnlyList<SbomComponentDto> Components,
    IReadOnlyList<SbomDependencyDto> Dependencies);

public sealed record SbomComponentDto(
    string Purl,
    string Name,
    string Version,
    string? Kind,
    string? License,
    IReadOnlyList<VulnerabilityDto> Vulnerabilities);

public sealed record VulnerabilityDto(
    string AdvisoryId,
    Severity Severity,
    string? Title,
    string? Description,
    string? FixedInVersion,
    string? ReferenceUrl,
    ScannerKind Source);

public sealed record SbomDependencyDto(
    string ParentPurl,
    string ChildPurl);
