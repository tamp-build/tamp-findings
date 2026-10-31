using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Api.Endpoints;

// The build get-or-create, shared by every ingest endpoint (component-collapse). A build
// (ComponentVersion) belongs to a project and carries a flavor tag (case-insensitive string).
//
// Build IDENTITY is the commit, not the version string. Evidence about one commit is one build, so
// two ingests that name the same commit resolve to the same build even when the producer stamped
// different version strings (e.g. "1.17.3" from one tool, "0.0.0+6648825" from another). Without
// this, a mismatched version silently spun up a phantom build that held one evidence type while the
// rest of the build's evidence sat elsewhere, and the ship gate read the split as "evidence missing".
// The version string is only the fallback key: with no commit it identifies the build; with a commit it can
// only adopt a build whose commit is not yet known — never one that belongs to a different commit (TFND-264).
//
// The `component`/`componentKind`/`componentProfile` fields ingest still sends are accepted for wire
// compatibility but no longer modelled — the build anchors straight to the project.
internal static class BuildResolver
{
    public static async Task<ComponentVersion> GetOrCreateAsync(
        FindingsDbContext db, Guid projectId, string? flavorRaw, string version,
        string? commitSha, string? branch, string? buildId, string? pullRequestRef,
        CancellationToken ct)
    {
        var flavor = string.IsNullOrWhiteSpace(flavorRaw) ? null : flavorRaw.Trim();
        var flavorLower = flavor?.ToLower();
        var sha = string.IsNullOrWhiteSpace(commitSha) ? null : commitSha.Trim();
        var pr = string.IsNullOrWhiteSpace(pullRequestRef) ? null : pullRequestRef.Trim();

        ComponentVersion? cv = null;

        // 1. Commit identity. Reconcile against any prior build for this (project, flavor) whose commit
        //    is the same — matched exactly or by git short/full-sha prefix. Scoped to the same PR
        //    context (both non-PR, or the same PR ref) so a PR head and a main build that happen to
        //    share a commit are never merged.
        if (sha is not null)
        {
            var candidates = await db.ComponentVersions
                .Where(v => v.ProjectId == projectId
                    && (flavorLower == null ? v.Flavor == null : v.Flavor != null && v.Flavor.ToLower() == flavorLower)
                    && v.CommitSha != null
                    && (pr == null ? v.PullRequestRef == null : v.PullRequestRef == pr))
                .ToListAsync(ct);
            cv = candidates.FirstOrDefault(v => ShaIdentifiesSameCommit(v.CommitSha!, sha));
        }

        // 2. Fallback on the version string.
        //    - No commit supplied: key on (project, flavor, version), as before.
        //    - A commit WAS supplied but matched no build: the version may only adopt a build that has NO
        //      commit yet (one created before its commit was known), in the same PR context. It must never
        //      adopt a build that already belongs to a DIFFERENT commit (TFND-264): a producer with a fixed
        //      product version would otherwise collapse every commit into the first one's build, keep that
        //      first sha, and replace-on-ingest would overwrite the earlier commit's evidence.
        if (cv is null)
        {
            var byVersion = db.ComponentVersions.Where(v =>
                v.ProjectId == projectId
                && (flavorLower == null ? v.Flavor == null : v.Flavor != null && v.Flavor.ToLower() == flavorLower)
                && v.VersionString == version);
            if (sha is not null)
                byVersion = byVersion.Where(v => v.CommitSha == null
                    && (pr == null ? v.PullRequestRef == null : v.PullRequestRef == pr));
            cv = await byVersion.FirstOrDefaultAsync(ct);
        }

        if (cv is null)
        {
            cv = new ComponentVersion
            {
                ProjectId = projectId,
                Flavor = flavor,
                VersionString = version,
                CommitSha = sha,
                BranchName = branch,
                BuildId = buildId,
                PullRequestRef = pr,
            };
            db.ComponentVersions.Add(cv);
        }
        else
        {
            // Enrich build context if a later ingest supplies more of it. Converge the commit on the
            // fuller sha so an abbreviated-then-full sequence ends up storing the full 40-char id.
            if (sha is not null && (cv.CommitSha is null || sha.Length > cv.CommitSha.Length)) cv.CommitSha = sha;
            if (branch is not null) cv.BranchName = branch;
            if (buildId is not null) cv.BuildId = buildId;
            if (pr is not null) cv.PullRequestRef = pr;
        }
        return cv;
    }

    // Two shas identify the same commit when one is a case-insensitive prefix of the other and the
    // shorter is a real abbreviated sha (>= 7 hex chars, git's default abbreviation). The length guard
    // stops a stray short token from matching unrelated commits.
    internal static bool ShaIdentifiesSameCommit(string a, string b)
    {
        if (a.Length > b.Length) (a, b) = (b, a);
        return a.Length >= 7 && b.StartsWith(a, StringComparison.OrdinalIgnoreCase);
    }
}
