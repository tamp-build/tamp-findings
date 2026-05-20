namespace Tamp.Findings.Api.Contracts;

// Module → class tree for the detail view's left pane. Source text and the
// line arrays are NOT included here to keep the payload light; the SPA pulls
// per-class detail (with source) on demand from /coverage/class/{id}.
public sealed record CoverageTreeResponse(
    bool Measured,
    double? SequenceCoverage,
    double? BranchCoverage,
    int CoveredSequences,
    int TotalSequences,
    IReadOnlyList<CoverageTreeModuleDto> Modules);

public sealed record CoverageTreeModuleDto(
    string Name,
    double SequenceCoverage,
    double BranchCoverage,
    int CoveredSequences,
    int TotalSequences,
    IReadOnlyList<CoverageTreeClassDto> Classes);

public sealed record CoverageTreeClassDto(
    Guid Id,
    string FullName,
    string SourceFileRelativePath,
    double SequenceCoverage,
    int CoveredSequences,
    int TotalSequences);

public sealed record CoverageClassDetailResponse(
    Guid Id,
    string ModuleName,
    string FullName,
    string SourceFileRelativePath,
    double SequenceCoverage,
    double BranchCoverage,
    int CoveredSequences,
    int TotalSequences,
    int CoveredBranches,
    int TotalBranches,
    int[] VisitedLines,
    int[] UnvisitedLines,
    string SourceText);
