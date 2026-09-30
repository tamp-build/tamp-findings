namespace Tamp.Findings.Api.Contracts;

// Analysis-coverage completeness intake (TFND-175). Build-identity fields mirror
// the other ingest contracts so BuildResolver reconciles on the commit.
public sealed record AnalysisCoverageIngestRequest(
    string Client,
    string Project,
    string? Flavor,
    string Version,
    string? CommitSha,
    string? Branch,
    string? BuildId,
    string? PullRequestRef,
    IReadOnlyList<AnalysisCoverageLanguageDto> Languages,
    AnalysisCoverageOverallDto? Overall = null,
    DateTimeOffset? ObservedAt = null,
    IngestActor? Actor = null);

public sealed record AnalysisCoverageLanguageDto(
    string Language,
    int FilesTotal,
    int FilesAnalyzed,
    long Loc,
    double PercentAnalyzed,
    IReadOnlyList<string>? AnalyzedByTools = null,
    IReadOnlyList<string>? UnanalyzedPaths = null);

public sealed record AnalysisCoverageOverallDto(
    IReadOnlyList<string>? LanguagesWithFootprintNoAnalyzer = null,
    IReadOnlyList<string>? Excludes = null);

public sealed record AnalysisCoverageIngestResponse(
    Guid ComponentVersionId,
    int LanguagesRecorded);
