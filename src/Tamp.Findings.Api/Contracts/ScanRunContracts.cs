using Tamp.Findings.Domain.Values;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Api.Contracts;

// Body of POST /ingest/scan-runs. Build orchestrator posts one of these
// per (scanner, ComponentVersion) at the end of every scan target.
public sealed record ScanRunIngestRequest(
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
    IReadOnlyList<ScanRunReceiptDto> Receipts);

public sealed record ScanRunReceiptDto(
    ScannerKind Scanner,
    ScanRunStatus Status,
    DateTimeOffset StartedAt,
    DateTimeOffset CompletedAt,
    int FindingsCount,
    string? ToolName,
    string? ToolVersion,
    string? Notes);

public sealed record ScanRunIngestResponse(
    Guid ComponentVersionId,
    int ReceiptsUpserted);

// Per-scanner state surfaced on /aggregates so the SPA can render
// "scanned · clean" vs "never scanned" without re-querying.
public sealed record ScanRunSummaryDto(
    ScannerKind Scanner,
    ScanRunStatus Status,
    DateTimeOffset CompletedAt,
    int FindingsCount,
    string? ToolName,
    string? ToolVersion);
