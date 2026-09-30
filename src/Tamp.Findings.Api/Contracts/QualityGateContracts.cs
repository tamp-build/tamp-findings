namespace Tamp.Findings.Api.Contracts;

// Attested quality-gate verdict intake (TFND-175). Build-identity fields mirror the
// other ingest contracts so BuildResolver reconciles on the commit.
public sealed record QualityGateIngestRequest(
    string Client,
    string Project,
    string? Flavor,
    string Version,
    string? CommitSha,
    string? Branch,
    string? BuildId,
    string? PullRequestRef,
    string Status,                                         // "pass" | "fail" | "warn"
    IReadOnlyList<QualityGateConditionDto>? Conditions,
    string? AnalysisId,
    System.Text.Json.JsonElement? Measures,               // opaque measures object, stored as JSON
    string? Source = null,
    DateTimeOffset? ObservedAt = null,
    IngestActor? Actor = null);

public sealed record QualityGateConditionDto(
    string Metric,
    string? Op,
    string? Threshold,
    string? Actual,
    string? Status);

public sealed record QualityGateIngestResponse(
    Guid ComponentVersionId,
    string Status,
    bool Blocks);
