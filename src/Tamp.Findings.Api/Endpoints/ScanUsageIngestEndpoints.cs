using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Api.Authentication;
using Tamp.Findings.Api.Contracts;
using Tamp.Findings.Application.Auditing;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Api.Endpoints;

// TFND-204: ingest LLM usage telemetry for a build's scans. Replace-on-ingest per ComponentVersion.
public static class ScanUsageIngestEndpoints
{
    public static IEndpointRouteBuilder MapScanUsageIngest(this IEndpointRouteBuilder app)
    {
        app.MapPost("/ingest/scan-usage", IngestAsync)
           .WithName("IngestScanUsage")
           .WithSummary("Replace-on-ingest LLM usage (tokens/model/latency) for a build's scans. Cost is computed by findings from the dated pricing table — do not send it. Requires Authorization: Bearer cli_… or prj_…")
           .AllowAnonymous()
           .AddEndpointFilter<IngestAuthFilter>();
        return app;
    }

    private static async Task<IResult> IngestAsync(ScanUsageIngestRequest req, HttpContext ctx, FindingsDbContext db, AuditLog audit, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(req.Client)) return Results.BadRequest("client required");
        if (string.IsNullOrWhiteSpace(req.Project)) return Results.BadRequest("project required");
        if (string.IsNullOrWhiteSpace(req.Version)) return Results.BadRequest("version required");

        var token = IngestAuthFilter.CurrentToken(ctx);
        var (_, project, scopeErr) = await IngestScopeGuard.ResolveAndGuardAsync(db, token, req.Client, req.Project, ct);
        if (scopeErr is not null) return scopeErr;

        var version = await BuildResolver.GetOrCreateAsync(db, project!.Id, req.Flavor, req.Version,
            req.CommitSha, req.Branch, req.BuildId, req.PullRequestRef, ct);
        version.ApplyActor(req.Actor);
        await db.SaveChangesAsync(ct);

        // Replace-on-ingest, like the other build evidence.
        await db.ScanUsageObservations.Where(u => u.ComponentVersionId == version.Id).ExecuteDeleteAsync(ct);

        var count = 0;
        foreach (var u in req.Usage ?? [])
        {
            if (string.IsNullOrWhiteSpace(u.ModelId)) continue;
            db.ScanUsageObservations.Add(new ScanUsageObservation
            {
                ComponentVersionId = version.Id,
                Adapter = string.IsNullOrWhiteSpace(u.Adapter) ? "unknown" : u.Adapter.Trim(),
                Capability = u.Capability,
                ModelId = u.ModelId.Trim(),
                Provider = u.Provider,
                InputTokens = Math.Max(0, u.InputTokens),
                OutputTokens = Math.Max(0, u.OutputTokens),
                LatencyMs = Math.Max(0, u.LatencyMs),
                ObservedAt = u.ObservedAt == default ? DateTimeOffset.UtcNow : u.ObservedAt,
            });
            count++;
        }
        await db.SaveChangesAsync(ct);

        await IngestAudit.RecordAsync(audit, db, token, version.Id,
            $"scan-usage: {count} observations — {req.Project}@{req.Version}", ct);
        await db.SaveChangesAsync(ct);

        return Results.Ok(new ScanUsageIngestResponse(version.Id, count));
    }
}
