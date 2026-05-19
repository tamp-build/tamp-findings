using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Api.Contracts;

// v0 ingest payload. Adopters POST this to /ingest/findings; the server
// find-or-creates Client/Project/Component(/Flavor)/ComponentVersion from
// the names, then upserts findings using the (component-version, hash)
// dedup invariant. Idempotent re-ingest is the goal: posting the same
// payload twice should produce the same row count and bump LastSeen.
public sealed record IngestRequest(
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
    ScannerKind Scanner,
    IReadOnlyList<IngestFinding> Findings);

public sealed record IngestFinding(
    string RuleId,
    Severity Severity,
    string Title,
    string? Description,
    string? FilePath,
    int? Line,
    string? Snippet);

public sealed record IngestResponse(
    Guid ComponentVersionId,
    int FindingsInserted,
    int FindingsUpdated);
