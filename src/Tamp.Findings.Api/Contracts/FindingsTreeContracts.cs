using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Api.Contracts;

public sealed record FindingsTreeResponse(
    int TotalCount,
    SeverityCounts Counts,
    IReadOnlyList<FindingsTreeModuleDto> Modules,
    // Findings without a usable FilePath (rare — typically CVEs without a
    // line target). Surfaced as a footnote in the SPA tree.
    int NoPathCount);

public sealed record FindingsTreeModuleDto(
    string Name,
    SeverityCounts Counts,
    IReadOnlyList<FindingsTreeFileDto> Files);

public sealed record FindingsTreeFileDto(
    string RelativePath,
    SeverityCounts Counts,
    Severity MaxSeverity);

public sealed record FindingsFileResponse(
    string RelativePath,
    bool SourceAvailable,
    string SourceText,
    IReadOnlyList<FindingsFileItemDto> Findings);

public sealed record FindingsFileItemDto(
    Guid Id,
    ScannerKind Scanner,
    string RuleId,
    Severity Severity,
    string Title,
    string? Description,
    int? Line);
