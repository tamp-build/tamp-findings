using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Api.Endpoints;

public sealed record BuildReceiptDto(
    Guid ComponentVersionId,
    Guid ComponentId,
    string ComponentName,
    string? FlavorName,
    string VersionString,
    string? CommitSha,
    string? BranchName,
    string? BuildId,
    DateTimeOffset CreatedAt,
    IReadOnlyList<ScanReceiptRowDto> Receipts);

public sealed record ScanReceiptRowDto(
    ScannerKind Scanner,
    ScanRunStatus Status,
    DateTimeOffset? StartedAt,
    DateTimeOffset? CompletedAt,
    int FindingsCount,
    string? ToolName,
    string? ToolVersion);

public sealed record ProjectScanReceiptsResponse(IReadOnlyList<BuildReceiptDto> Builds);

public static class ProjectScanReceiptsEndpoints
{
    public static IEndpointRouteBuilder MapProjectScanReceipts(this IEndpointRouteBuilder app)
    {
        app.MapGet("/projects/{projectId:guid}/scan-receipts", ListAsync)
           .WithName("ListProjectScanReceipts")
           .WithSummary("Per-build scanner receipts for a project. One row per ComponentVersion (newest first) with its set of scan-run receipts.")
           .WithTags("Risk");
        return app;
    }

    private static async Task<Ok<ProjectScanReceiptsResponse>> ListAsync(
        Guid projectId, FindingsDbContext db, CancellationToken ct,
        int take = 25, bool includeNonCanonical = false)
    {
        take = Math.Clamp(take, 1, 200);

        // Default to canonical-only — mirrors the score-side filter
        // (acceptance-gate posture). The SPA filter toggle flips this
        // to true to surface PR/branch builds in the receipts panel.
        IQueryable<ComponentVersion> q = db.ComponentVersions.AsNoTracking()
            .Where(v => v.Component!.ProjectId == projectId);
        if (!includeNonCanonical)
        {
            q = q.Where(v => v.PullRequestRef == null
                          && (v.BranchName == null || v.BranchName == "main" || v.BranchName == "master"));
        }

        // Latest CVs in the project — ordered by CreatedAt desc. CVs
        // without any receipts are still surfaced so the user can see a
        // build cycle that scheduled but produced no scan output yet.
        var cvs = await q
            .OrderByDescending(v => v.CreatedAt)
            .Take(take)
            .Select(v => new
            {
                v.Id, v.ComponentId, v.VersionString, v.CommitSha,
                v.BranchName, v.BuildId, v.CreatedAt,
                ComponentName = v.Component!.Name,
                FlavorName = v.Flavor != null ? v.Flavor.Name : null,
            })
            .ToListAsync(ct);

        if (cvs.Count == 0)
            return TypedResults.Ok(new ProjectScanReceiptsResponse([]));

        var cvIds = cvs.Select(c => c.Id).ToList();
        var receipts = await db.ScanRunReceipts.AsNoTracking()
            .Where(r => cvIds.Contains(r.ComponentVersionId))
            .ToListAsync(ct);
        var receiptsByCv = receipts
            .GroupBy(r => r.ComponentVersionId)
            .ToDictionary(g => g.Key, g => g.OrderBy(r => r.Scanner.ToString()).ToList());

        var builds = cvs.Select(c => new BuildReceiptDto(
            c.Id, c.ComponentId, c.ComponentName, c.FlavorName,
            c.VersionString, c.CommitSha, c.BranchName, c.BuildId, c.CreatedAt,
            receiptsByCv.TryGetValue(c.Id, out var rs)
                ? rs.Select(r => new ScanReceiptRowDto(
                    r.Scanner, r.Status, r.StartedAt, r.CompletedAt,
                    r.FindingsCount, r.ToolName, r.ToolVersion)).ToList()
                : (IReadOnlyList<ScanReceiptRowDto>)[]
        )).ToList();

        return TypedResults.Ok(new ProjectScanReceiptsResponse(builds));
    }
}
