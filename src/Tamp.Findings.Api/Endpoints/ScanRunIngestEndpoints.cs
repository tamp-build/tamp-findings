using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Api.Authentication;
using Tamp.Findings.Api.Contracts;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;

using Tamp.Findings.Application.Auditing;

namespace Tamp.Findings.Api.Endpoints;

public static class ScanRunIngestEndpoints
{
    public static IEndpointRouteBuilder MapScanRunIngest(this IEndpointRouteBuilder app)
    {
        app.MapPost("/ingest/scan-runs", IngestAsync)
           .WithName("IngestScanRuns")
           .WithSummary("Replace-on-ingest receipts per (ComponentVersion, Scanner). A scanner without a receipt is treated as 'never ran' on the dashboard, so emit one even when the scan ran clean. Requires Authorization: Bearer cli_… or prj_…")
           .AllowAnonymous()
           .AddEndpointFilter<IngestAuthFilter>();
        return app;
    }

    private static async Task<IResult> IngestAsync(ScanRunIngestRequest req, HttpContext ctx, FindingsDbContext db, AuditLog audit, Tamp.Findings.Application.Projects.ScoreSnapshotService snapshots, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(req.Client)) return Results.BadRequest("client required");
        if (string.IsNullOrWhiteSpace(req.Project)) return Results.BadRequest("project required");
        if (string.IsNullOrWhiteSpace(req.Version)) return Results.BadRequest("version required");

        var token = IngestAuthFilter.CurrentToken(ctx);
        var (resolved, scopeErr) = await ResolveCvAsync(db, token, req, ct);
        if (scopeErr is not null) return scopeErr;
        var version = resolved!;

        var upserted = 0;
        foreach (var r in req.Receipts ?? [])
        {
            var existing = await db.ScanRunReceipts
                .FirstOrDefaultAsync(x => x.ComponentVersionId == version.Id && x.Scanner == r.Scanner, ct);
            if (existing is null)
            {
                db.ScanRunReceipts.Add(new ScanRunReceipt
                {
                    ComponentVersionId = version.Id,
                    Scanner = r.Scanner,
                    Status = r.Status,
                    StartedAt = r.StartedAt,
                    CompletedAt = r.CompletedAt,
                    FindingsCount = r.FindingsCount,
                    ToolName = r.ToolName,
                    ToolVersion = r.ToolVersion,
                    Notes = r.Notes,
                    GateStatus = r.GateStatus,
                    GateDetails = r.GateDetails,
                });
            }
            else
            {
                existing.Status = r.Status;
                existing.StartedAt = r.StartedAt;
                existing.CompletedAt = r.CompletedAt;
                existing.FindingsCount = r.FindingsCount;
                existing.ToolName = r.ToolName;
                existing.ToolVersion = r.ToolVersion;
                existing.Notes = r.Notes;
                existing.GateStatus = r.GateStatus;
                existing.GateDetails = r.GateDetails;
                existing.IngestedAt = DateTimeOffset.UtcNow;
            }
            upserted++;
        }
        await db.SaveChangesAsync(ct);

        await IngestAudit.RecordAsync(audit, db, token, version.Id,
            $"scan-runs: {upserted} receipts — {req.Project}@{req.Version}", ct);
        await db.SaveChangesAsync(ct);

        await snapshots.RecordForBuildAsync(version.Id, ct);   // TFND-176: receipts move the missing-scanners score

        return Results.Ok(new ScanRunIngestResponse(version.Id, upserted));
    }

    private static async Task<(ComponentVersion? version, IResult? error)> ResolveCvAsync(
        FindingsDbContext db, IngestToken? token, ScanRunIngestRequest req, CancellationToken ct)
    {
        var (_, project, scopeErr) = await IngestScopeGuard.ResolveAndGuardAsync(db, token, req.Client, req.Project, ct);
        if (scopeErr is not null) return (null, scopeErr);

        var version = await BuildResolver.GetOrCreateAsync(db, project!.Id, req.Flavor, req.Version,
            req.CommitSha, req.Branch, req.BuildId, req.PullRequestRef, ct);

        // TFND-165: stamp the build with the actor that produced this ingest,
        // whether it was just created or already existed.
        version.ApplyActor(req.Actor);
        await db.SaveChangesAsync(ct);
        return (version, null);
    }
}
