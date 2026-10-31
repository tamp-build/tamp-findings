using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Api.Contracts;

/// <summary>
/// The build an ingest actually landed on (TFND-266), echoed in every single-build ingest response.
///
/// A producer can only log what it SENT; this is what the server RESOLVED. Compare <see cref="CommitSha"/> with the
/// commit you posted: they should agree. Evidence for one commit always lands on one build, whatever version string
/// was stamped on it, and two commits are two builds even with the same version string (TFND-264). See
/// docs/VERSIONING.md, "The ingest contract across versions".
/// </summary>
/// <param name="ComponentVersionId">The build's id (also returned as the response's componentVersionId).</param>
/// <param name="VersionString">The version string the build was created with (a later ingest for the same commit
/// with a different version string reuses the build and does not change it).</param>
/// <param name="CommitSha">The build's commit: the full sha once any ingest supplied it.</param>
/// <param name="Flavor">The build's flavor tag (e.g. "linux", "web"), or null.</param>
/// <param name="Branch">The branch most recently reported for the build, or null.</param>
/// <param name="PullRequestRef">The PR context, or null for a non-PR build.</param>
/// <param name="CreatedAt">When the build was first seen.</param>
public sealed record ResolvedBuild(
    Guid ComponentVersionId,
    string VersionString,
    string? CommitSha,
    string? Flavor,
    string? Branch,
    string? PullRequestRef,
    DateTimeOffset CreatedAt)
{
    public static ResolvedBuild From(ComponentVersion v) =>
        new(v.Id, v.VersionString, v.CommitSha, v.Flavor, v.BranchName, v.PullRequestRef, v.CreatedAt);
}
