namespace Tamp.Findings.Api.Contracts;

public sealed record CoverageIngestRequest(
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
    string ToolName,
    string? ToolVersion,
    double SequenceCoverage,
    double BranchCoverage,
    int CoveredSequences,
    int TotalSequences,
    int CoveredBranches,
    int TotalBranches,
    IReadOnlyList<CoverageModuleDto> Modules,
    // SourceFiles are deduped at the request level so partial classes that
    // share a file don't transmit the same body twice. Can be omitted when
    // the producer doesn't have source-file content (e.g. SARIF-only flow).
    IReadOnlyList<CoverageSourceFileDto>? SourceFiles = null);

public sealed record CoverageModuleDto(
    string Name,
    double SequenceCoverage,
    double BranchCoverage,
    int CoveredSequences,
    int TotalSequences,
    IReadOnlyList<CoverageClassDto>? Classes = null);

// Per-class coverage. SourceFileRelativePath is the path normalised relative
// to the repo root (e.g. "src/Tamp.Findings.Api/Endpoints/Aggregates.cs"),
// keyed against the SourceFiles list at the top of the ingest payload to
// avoid posting the same file body twice for partial classes.
public sealed record CoverageClassDto(
    string FullName,
    string SourceFileRelativePath,
    double SequenceCoverage,
    double BranchCoverage,
    int CoveredSequences,
    int TotalSequences,
    int CoveredBranches,
    int TotalBranches,
    int[] VisitedLines,
    int[] UnvisitedLines);

public sealed record CoverageSourceFileDto(
    string RelativePath,
    string? AbsolutePath,
    string SourceText);

public sealed record CoverageIngestResponse(
    Guid ComponentVersionId,
    Guid CoverageReportId,
    int ModulesCount,
    int ClassesCount,
    int SourceFilesCount);
