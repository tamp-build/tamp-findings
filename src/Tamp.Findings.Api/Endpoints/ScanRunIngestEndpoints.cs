using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Api.Authentication;
using Tamp.Findings.Api.Contracts;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;

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

    private static async Task<IResult> IngestAsync(ScanRunIngestRequest req, HttpContext ctx, FindingsDbContext db, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(req.Client)) return Results.BadRequest("client required");
        if (string.IsNullOrWhiteSpace(req.Project)) return Results.BadRequest("project required");
        if (string.IsNullOrWhiteSpace(req.Component)) return Results.BadRequest("component required");
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
                existing.IngestedAt = DateTimeOffset.UtcNow;
            }
            upserted++;
        }
        await db.SaveChangesAsync(ct);

        return Results.Ok(new ScanRunIngestResponse(version.Id, upserted));
    }

    private static async Task<(ComponentVersion? version, IResult? error)> ResolveCvAsync(
        FindingsDbContext db, IngestToken? token, ScanRunIngestRequest req, CancellationToken ct)
    {
        var (_, project, scopeErr) = await IngestScopeGuard.ResolveAndGuardAsync(db, token, req.Client, req.Project, ct);
        if (scopeErr is not null) return (null, scopeErr);

        var component = await db.Components.FirstOrDefaultAsync(c => c.ProjectId == project!.Id && c.Name == req.Component, ct)
            ?? db.Components.Add(new Component { ProjectId = project!.Id, Name = req.Component, Kind = req.ComponentKind }).Entity;
        ComponentFlavor? flavor = null;
        if (!string.IsNullOrWhiteSpace(req.Flavor))
        {
            flavor = await db.ComponentFlavors.FirstOrDefaultAsync(f => f.ComponentId == component.Id && f.Name == req.Flavor, ct)
                ?? db.ComponentFlavors.Add(new ComponentFlavor { ComponentId = component.Id, Name = req.Flavor }).Entity;
        }
        var version = await db.ComponentVersions.FirstOrDefaultAsync(v =>
            v.ComponentId == component.Id &&
            v.FlavorId == (flavor != null ? flavor.Id : (Guid?)null) &&
            v.VersionString == req.Version, ct);
        if (version is null)
        {
            version = new ComponentVersion
            {
                ComponentId = component.Id,
                FlavorId = flavor?.Id,
                VersionString = req.Version,
                CommitSha = req.CommitSha,
                BranchName = req.Branch,
                BuildId = req.BuildId,
                PullRequestRef = req.PullRequestRef,
            };
            db.ComponentVersions.Add(version);
        }
        await db.SaveChangesAsync(ct);
        return (version, null);
    }
}
