using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Api.Authentication;
using Tamp.Findings.Api.Contracts;
using Tamp.Findings.Application.Auditing;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Api.Endpoints;

// Attested quality-gate verdict intake (TFND-175). The producer attests the gate
// (pass/fail/warn + failing conditions); findings records it and gates on it
// (qualityGate → SA-15). Replace-on-ingest per build.
public static class QualityGateIngestEndpoints
{
    public static IEndpointRouteBuilder MapQualityGateIngest(this IEndpointRouteBuilder app)
    {
        app.MapPost("/ingest/quality-gate", IngestAsync)
           .WithName("IngestQualityGate")
           .WithSummary("Attested code-quality gate verdict (SonarQube-style pass/fail/warn + conditions + measures) for a build. Feeds the qualityGate gate (SA-15). Requires Authorization: Bearer cli_… or prj_…")
           .AllowAnonymous()
           .AddEndpointFilter<IngestAuthFilter>();
        return app;
    }

    private static async Task<IResult> IngestAsync(
        QualityGateIngestRequest req, HttpContext ctx, FindingsDbContext db, AuditLog audit,
        Tamp.Findings.Application.Projects.ScoreSnapshotService snapshots, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(req.Client)) return Results.BadRequest("client required");
        if (string.IsNullOrWhiteSpace(req.Project)) return Results.BadRequest("project required");
        if (string.IsNullOrWhiteSpace(req.Version)) return Results.BadRequest("version required");
        if (string.IsNullOrWhiteSpace(req.Status)) return Results.BadRequest("status required");

        var token = IngestAuthFilter.CurrentToken(ctx);
        var (_, project, scopeErr) = await IngestScopeGuard.ResolveAndGuardAsync(db, token, req.Client, req.Project, ct);
        if (scopeErr is not null) return scopeErr;

        var version = await BuildResolver.GetOrCreateAsync(db, project!.Id, req.Flavor, req.Version,
            req.CommitSha, req.Branch, req.BuildId, req.PullRequestRef, ct);

        // Normalise the tool's native verdicts; an unrecognised value must not silently read as non-blocking.
        var status = req.Status.Trim().ToLowerInvariant() switch
        {
            "pass" or "ok" or "passed" => "pass",
            "fail" or "error" or "failed" => "fail",
            "warn" or "warning" => "warn",
            _ => null,
        };
        if (status is null) return Results.BadRequest("status must be one of pass, fail, warn (or the tool's OK / ERROR / WARN)");

        var existing = await db.QualityGateResults
            .FirstOrDefaultAsync(r => r.ComponentVersionId == version.Id, ct);
        if (existing is null)
        {
            existing = new QualityGateResult { ComponentVersionId = version.Id };
            db.QualityGateResults.Add(existing);
        }
        existing.Status = status;
        existing.ConditionsJson = req.Conditions is { Count: > 0 } ? JsonSerializer.Serialize(req.Conditions) : null;
        existing.MeasuresJson = req.Measures is { } m ? m.GetRawText() : null;
        existing.AnalysisId = req.AnalysisId;
        existing.Source = req.Source;
        existing.ObservedAt = req.ObservedAt ?? DateTimeOffset.UtcNow;
        existing.IngestedAt = DateTimeOffset.UtcNow;

        await db.SaveChangesAsync(ct);
        await IngestAudit.RecordAsync(audit, db, token, version.Id,
            $"quality-gate: {status} — {req.Project}@{req.Version}", ct);
        await db.SaveChangesAsync(ct);

        await snapshots.RecordForBuildAsync(version.Id, ct);

        return Results.Ok(new QualityGateIngestResponse(version.Id, status, Blocks: status == "fail"));
    }
}
