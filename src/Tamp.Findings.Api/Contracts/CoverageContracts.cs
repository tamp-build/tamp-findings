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
    IReadOnlyList<CoverageModuleDto> Modules);

public sealed record CoverageModuleDto(
    string Name,
    double SequenceCoverage,
    double BranchCoverage,
    int CoveredSequences,
    int TotalSequences);

public sealed record CoverageIngestResponse(
    Guid ComponentVersionId,
    Guid CoverageReportId,
    int ModulesCount);
