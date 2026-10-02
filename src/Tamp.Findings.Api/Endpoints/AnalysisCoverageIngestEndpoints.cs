using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Api.Authentication;
using Tamp.Findings.Api.Contracts;
using Tamp.Findings.Application.Auditing;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Api.Endpoints;

// Analysis-coverage completeness intake (TFND-175). The producer (full checkout)
// reports what fraction of each language was actually put through an analyzer;
// findings gates on it so "0 findings" only credits SA-11 when coverage is real.
// Replace-on-ingest per build.
public static class AnalysisCoverageIngestEndpoints
{
    public static IEndpointRouteBuilder MapAnalysisCoverageIngest(this IEndpointRouteBuilder app)
    {
        app.MapPost("/ingest/analysis-coverage", IngestAsync)
           .WithName("IngestAnalysisCoverage")
           .WithSummary("Per-language analysis-coverage completeness for a build (what was analyzed, by which tool, what's unanalyzed). Distinct from test coverage. Feeds the analysisCoverage gate. Requires Authorization: Bearer cli_… or prj_…")
           .AllowAnonymous()
           .AddEndpointFilter<IngestAuthFilter>();
        return app;
    }

    private static async Task<IResult> IngestAsync(
        AnalysisCoverageIngestRequest req, HttpContext ctx, FindingsDbContext db, AuditLog audit,
        Tamp.Findings.Application.Projects.ScoreSnapshotService snapshots, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(req.Client)) return Results.BadRequest("client required");
        if (string.IsNullOrWhiteSpace(req.Project)) return Results.BadRequest("project required");
        if (string.IsNullOrWhiteSpace(req.Version)) return Results.BadRequest("version required");

        var token = IngestAuthFilter.CurrentToken(ctx);
        var (_, project, scopeErr) = await IngestScopeGuard.ResolveAndGuardAsync(db, token, req.Client, req.Project, ct);
        if (scopeErr is not null) return scopeErr;

        var version = await BuildResolver.GetOrCreateAsync(db, project!.Id, req.Flavor, req.Version,
            req.CommitSha, req.Branch, req.BuildId, req.PullRequestRef, ct);

        // Replace-on-ingest: one report per build.
        var existing = await db.AnalysisCoverageReports
            .Where(r => r.ComponentVersionId == version.Id).ToListAsync(ct);
        if (existing.Count > 0) db.AnalysisCoverageReports.RemoveRange(existing);

        var report = new AnalysisCoverageReport
        {
            ComponentVersionId = version.Id,
            ObservedAt = req.ObservedAt ?? DateTimeOffset.UtcNow,
            GapLanguages = Join(req.Overall?.LanguagesWithFootprintNoAnalyzer),
            Excludes = Join(req.Overall?.Excludes),
            Languages = (req.Languages ?? []).Select(l => new AnalysisCoverageLanguage
            {
                Language = l.Language,
                FilesTotal = l.FilesTotal,
                FilesAnalyzed = l.FilesAnalyzed,
                LinesTotal = l.Loc,
                LinesAnalyzed = (long)(l.Loc * Math.Clamp(l.PercentAnalyzed, 0, 100) / 100.0),
                AnalyzedBy = Join(l.AnalyzedByTools),
                PercentAnalyzed = l.PercentAnalyzed,
                UnanalyzedSample = Join(l.UnanalyzedPaths, limit: 50),
            }).ToList(),
        };
        db.AnalysisCoverageReports.Add(report);
        await db.SaveChangesAsync(ct);

        await IngestAudit.RecordAsync(audit, db, token, version.Id,
            $"analysis-coverage: {report.Languages.Count} languages — {req.Project}@{req.Version}", ct);
        await db.SaveChangesAsync(ct);

        await snapshots.RecordForBuildAsync(version.Id, ct);

        return Results.Ok(new AnalysisCoverageIngestResponse(version.Id, report.Languages.Count));
    }

    private static string? Join(IReadOnlyList<string>? items, int limit = 1000)
    {
        if (items is not { Count: > 0 }) return null;
        var take = items.Count > limit ? items.Take(limit) : items;
        return string.Join(", ", take);
    }
}
