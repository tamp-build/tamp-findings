using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Api.Contracts;

// TFND-204: LLM usage/cost telemetry for a build's scans (conformance adapters etc.). Replace-on-ingest
// per ComponentVersion. Cost is NOT sent — findings owns the dated pricing table and computes it.
public sealed record ScanUsageIngestRequest(
    string Client,
    string Project,
    string? Component,
    string? ComponentKind,
    string? Flavor,
    string Version,
    string? CommitSha,
    string? Branch,
    string? BuildId,
    string? PullRequestRef,
    IReadOnlyList<ScanUsageDto> Usage,
    IngestActor? Actor = null);

public sealed record ScanUsageDto(
    string Adapter,          // "adr-conformance", "reverse-exam", …
    string ModelId,          // "claude-opus-4-8", "gpt-4o", …
    string? Provider,        // "anthropic" | "openai" | "bedrock"
    string? Capability,
    long InputTokens,
    long OutputTokens,
    double LatencyMs,
    DateTimeOffset ObservedAt);

public sealed record ScanUsageIngestResponse(Guid ComponentVersionId, int Observations);
