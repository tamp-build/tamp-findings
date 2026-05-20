using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Api.Contracts;

// Mirrors the build-side TestResultsIngestMapper output. Ingest is
// replace-on-ingest per ComponentVersion (one report).
public sealed record TestResultsIngestRequest(
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
    int TotalCount,
    int PassedCount,
    int FailedCount,
    int SkippedCount,
    int InconclusiveCount,
    double DurationMs,
    DateTimeOffset StartedAt,
    DateTimeOffset CompletedAt,
    IReadOnlyList<TestSuiteRequestDto> Suites);

public sealed record TestSuiteRequestDto(
    string AssemblyName,
    string ClassName,
    int TotalCount,
    int PassedCount,
    int FailedCount,
    int SkippedCount,
    int InconclusiveCount,
    double DurationMs,
    IReadOnlyList<TestCaseRequestDto> Cases);

public sealed record TestCaseRequestDto(
    string Name,
    TestOutcome Outcome,
    double DurationMs,
    string? ErrorMessage,
    string? ErrorStackTrace);

public sealed record TestResultsIngestResponse(
    Guid ComponentVersionId,
    Guid TestRunReportId,
    int SuitesCount,
    int CasesCount);

// Read shape powering the Tests tab and the Overview tile.
public sealed record TestResultsTreeResponse(
    bool Measured,
    int TotalCount,
    int PassedCount,
    int FailedCount,
    int SkippedCount,
    int InconclusiveCount,
    double DurationMs,
    DateTimeOffset? CompletedAt,
    IReadOnlyList<TestTreeAssemblyDto> Assemblies);

public sealed record TestTreeAssemblyDto(
    string Name,
    int TotalCount,
    int PassedCount,
    int FailedCount,
    int SkippedCount,
    IReadOnlyList<TestTreeSuiteDto> Suites);

public sealed record TestTreeSuiteDto(
    Guid Id,
    string ClassName,
    int TotalCount,
    int PassedCount,
    int FailedCount,
    int SkippedCount);

public sealed record TestSuiteDetailResponse(
    Guid Id,
    string AssemblyName,
    string ClassName,
    int TotalCount,
    int PassedCount,
    int FailedCount,
    int SkippedCount,
    double DurationMs,
    IReadOnlyList<TestCaseDetailDto> Cases);

public sealed record TestCaseDetailDto(
    string Name,
    TestOutcome Outcome,
    double DurationMs,
    string? ErrorMessage,
    string? ErrorStackTrace);
