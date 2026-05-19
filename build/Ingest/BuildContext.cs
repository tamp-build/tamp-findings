namespace Tamp.Findings.Build.Ingest;

// Static build-context fields the build orchestrator stamps onto every
// ingest payload. Stays in build/ — the API doesn't know or care that
// this is how tamp.findings dogfoods itself.
public sealed record IngestBuildContext(
    string Client,
    string Project,
    string Component,
    string? ComponentKind,
    string? Flavor,
    string Version,
    string? CommitSha,
    string? Branch,
    string? BuildId,
    string? PullRequestRef);
