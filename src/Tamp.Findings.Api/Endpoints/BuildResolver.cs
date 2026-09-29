using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Api.Endpoints;

// The build get-or-create, shared by every ingest endpoint (component-collapse). A build
// (ComponentVersion) is keyed on (project, flavor, version); flavor is a case-insensitive string
// tag. The `component`/`componentKind`/`componentProfile` fields ingest still sends are accepted
// for wire compatibility but no longer modelled — the build anchors straight to the project.
internal static class BuildResolver
{
    public static async Task<ComponentVersion> GetOrCreateAsync(
        FindingsDbContext db, Guid projectId, string? flavorRaw, string version,
        string? commitSha, string? branch, string? buildId, string? pullRequestRef,
        CancellationToken ct)
    {
        var flavor = string.IsNullOrWhiteSpace(flavorRaw) ? null : flavorRaw.Trim();
        var flavorLower = flavor?.ToLower();

        var cv = await db.ComponentVersions.FirstOrDefaultAsync(v =>
            v.ProjectId == projectId
            && (flavorLower == null ? v.Flavor == null : v.Flavor != null && v.Flavor.ToLower() == flavorLower)
            && v.VersionString == version, ct);

        if (cv is null)
        {
            cv = new ComponentVersion
            {
                ProjectId = projectId,
                Flavor = flavor,
                VersionString = version,
                CommitSha = commitSha,
                BranchName = branch,
                BuildId = buildId,
                PullRequestRef = pullRequestRef,
            };
            db.ComponentVersions.Add(cv);
        }
        else
        {
            // Enrich build context if a later ingest supplies more of it.
            if (commitSha is not null) cv.CommitSha = commitSha;
            if (branch is not null) cv.BranchName = branch;
            if (buildId is not null) cv.BuildId = buildId;
            if (pullRequestRef is not null) cv.PullRequestRef = pullRequestRef;
        }
        return cv;
    }
}
