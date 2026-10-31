namespace Tamp.Findings.Api.Contracts;

// TFND-265: the read-back for an ingest token. A producer that posted evidence for a commit can ask the server what it
// actually holds for that commit, using the same cli_/prj_ token it posted with, instead of trusting the 200s it got.
// Summaries only: counts, percentages, verdicts and timestamps; never finding bodies, source text or test names.

/// <summary>Everything the server holds for one commit of one project, as the ingest token that posted it can see it.</summary>
/// <param name="ProjectId">The project the commit was looked up in.</param>
/// <param name="Client">The client's stored name.</param>
/// <param name="Project">The project's stored name.</param>
/// <param name="CommitSha">The commit as requested (a 7+ character prefix matches the stored full sha).</param>
/// <param name="Builds">One entry per build of this commit: a commit has more than one build only when it was built in
/// more than one flavor or PR context.</param>
public sealed record BuildEvidenceResponse(
    Guid ProjectId,
    string Client,
    string Project,
    string CommitSha,
    IReadOnlyList<BuildEvidence> Builds);

/// <summary>The evidence held for one build. A null section (or an empty list) means none of that evidence was stored.</summary>
public sealed record BuildEvidence(
    ResolvedBuild Build,
    CoverageEvidence? Coverage,
    TestResultsEvidence? TestResults,
    SbomEvidence? Sbom,
    IReadOnlyList<ScannerFindingsEvidence> Findings,
    IReadOnlyList<ScanRunEvidence> ScanRuns,
    QualityGateEvidence? QualityGate,
    ContainerImageEvidence? ContainerImage,
    AnalysisCoverageEvidence? AnalysisCoverage,
    ScanUsageEvidence? ScanUsage,
    int ConformanceVerdicts,
    int Diagnostics);

/// <summary>The stored test-coverage report. Module, source-file and class counts show how much of a large report was kept.</summary>
public sealed record CoverageEvidence(
    string ToolName,
    string? ToolVersion,
    double SequenceCoverage,
    double BranchCoverage,
    int CoveredSequences,
    int TotalSequences,
    int CoveredBranches,
    int TotalBranches,
    int Modules,
    int SourceFiles,
    int Classes,
    DateTimeOffset IngestedAt);

/// <summary>The stored test-run report. Suites and Cases count the rows kept, as a check against the report's own totals.</summary>
public sealed record TestResultsEvidence(
    string ToolName,
    string? ToolVersion,
    int Total,
    int Passed,
    int Failed,
    int Skipped,
    int Inconclusive,
    int Suites,
    int Cases,
    DateTimeOffset CompletedAt,
    DateTimeOffset IngestedAt);

/// <summary>The stored SBOM snapshot and whether provenance has been attached to it.</summary>
public sealed record SbomEvidence(
    Guid SnapshotId,
    string? ToolName,
    string? ToolVersion,
    string? SpecVersion,
    string? SerialNumber,
    int Components,
    int Vulnerabilities,
    string? ProvenanceType,
    bool ProvenanceVerified,
    DateTimeOffset IngestedAt);

/// <summary>Findings one scanner reported for the build. OpenBySeverity is keyed by severity name (Critical, High, …).</summary>
public sealed record ScannerFindingsEvidence(
    string Scanner,
    int Total,
    int Open,
    IReadOnlyDictionary<string, int> OpenBySeverity);

/// <summary>A scanner's receipt that it ran against the build.</summary>
public sealed record ScanRunEvidence(
    string Scanner,
    string Status,
    int FindingsCount,
    string? ToolName,
    string? ToolVersion,
    DateTimeOffset CompletedAt,
    DateTimeOffset IngestedAt);

/// <summary>The attested quality-gate verdict.</summary>
public sealed record QualityGateEvidence(
    string Status,
    string? Source,
    string? AnalysisId,
    DateTimeOffset ObservedAt,
    DateTimeOffset IngestedAt);

/// <summary>The image the build produced, and the base image behind it when one was identified.</summary>
public sealed record ContainerImageEvidence(
    string Reference,
    string? Digest,
    string? BaseImageReference,
    string? BaseImageDigest,
    DateTimeOffset InspectedAt);

/// <summary>The stored per-language analysis-coverage report.</summary>
public sealed record AnalysisCoverageEvidence(
    int Languages,
    string? GapLanguages,
    DateTimeOffset ObservedAt,
    DateTimeOffset IngestedAt);

/// <summary>LLM usage recorded for the build's scans.</summary>
public sealed record ScanUsageEvidence(
    int Observations,
    long InputTokens,
    long OutputTokens);
