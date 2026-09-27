using Tamp.Findings.Build.Adapters;

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
    string? PullRequestRef,
    // Who produced this build's ingest (tamp workerId → actor). Stamped onto
    // every payload so the dashboard attributes the CV to a human or an agent
    // (TFND-165). Null when unresolved — the API treats absent actor as legacy.
    IngestActorDto? Actor = null);
