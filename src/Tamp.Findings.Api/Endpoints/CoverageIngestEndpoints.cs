using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Api.Authentication;
using Tamp.Findings.Api.Contracts;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;

using Tamp.Findings.Application.Auditing;

namespace Tamp.Findings.Api.Endpoints;

public static class CoverageIngestEndpoints
{
    public static IEndpointRouteBuilder MapCoverageIngest(this IEndpointRouteBuilder app)
    {
        app.MapPost("/ingest/coverage", IngestAsync)
           .WithName("IngestCoverage")
           .WithSummary("Replace the coverage report for one component version. Replace-on-ingest: any prior report for the same CV is deleted before insert. Requires Authorization: Bearer cli_… or prj_…")
           .AllowAnonymous()
           .AddEndpointFilter<IngestAuthFilter>();
        return app;
    }

    private static async Task<IResult> IngestAsync(CoverageIngestRequest req, HttpContext ctx, FindingsDbContext db, AuditLog audit, Tamp.Findings.Application.Projects.ScoreSnapshotService snapshots, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(req.Client)) return Results.BadRequest("client required");
        if (string.IsNullOrWhiteSpace(req.Project)) return Results.BadRequest("project required");
        if (string.IsNullOrWhiteSpace(req.Version)) return Results.BadRequest("version required");

        var token = IngestAuthFilter.CurrentToken(ctx);
        var (resolved, scopeErr) = await ResolveCvAsync(db, token, req, ct);
        if (scopeErr is not null) return scopeErr;
        var version = resolved!;

        // Replace-on-ingest, like SBOM.
        var existing = await db.CoverageReports
            .Where(r => r.ComponentVersionId == version.Id)
            .ToListAsync(ct);
        if (existing.Count > 0)
        {
            db.CoverageReports.RemoveRange(existing);
            await db.SaveChangesAsync(ct);
        }

        var report = new CoverageReport
        {
            ComponentVersionId = version.Id,
            ToolName = req.ToolName,
            ToolVersion = req.ToolVersion,
            SequenceCoverage = req.SequenceCoverage,
            BranchCoverage = req.BranchCoverage,
            CoveredSequences = req.CoveredSequences,
            TotalSequences = req.TotalSequences,
            CoveredBranches = req.CoveredBranches,
            TotalBranches = req.TotalBranches,
            IngestedAt = DateTimeOffset.UtcNow,
        };
        db.CoverageReports.Add(report);
        await db.SaveChangesAsync(ct);

        // Source files first (deduped on relative path) so classes can FK to
        // them by lookup. EF Core gives us the inserted Id after SaveChangesAsync.
        var sourceFilesByPath = new Dictionary<string, CoverageSourceFile>(StringComparer.OrdinalIgnoreCase);
        foreach (var f in req.SourceFiles ?? [])
        {
            if (string.IsNullOrWhiteSpace(f.RelativePath)) continue;
            if (sourceFilesByPath.ContainsKey(f.RelativePath)) continue;
            var sf = new CoverageSourceFile
            {
                CoverageReportId = report.Id,
                RelativePath = f.RelativePath,
                AbsolutePath = f.AbsolutePath,
                SourceText = f.SourceText ?? "",
                LineCount = (f.SourceText ?? "").Count(c => c == '\n') + 1,
            };
            db.CoverageSourceFiles.Add(sf);
            sourceFilesByPath[f.RelativePath] = sf;
        }
        if (sourceFilesByPath.Count > 0) await db.SaveChangesAsync(ct);

        // Modules + their classes. Deduped on module name first, then on
        // (class FullName, source file) within the module.
        var seenModules = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var classCount = 0;
        foreach (var m in req.Modules)
        {
            if (string.IsNullOrWhiteSpace(m.Name)) continue;
            if (!seenModules.Add(m.Name)) continue;
            var module = new CoverageModule
            {
                CoverageReportId = report.Id,
                Name = m.Name,
                SequenceCoverage = m.SequenceCoverage,
                BranchCoverage = m.BranchCoverage,
                CoveredSequences = m.CoveredSequences,
                TotalSequences = m.TotalSequences,
            };
            db.CoverageModules.Add(module);
            await db.SaveChangesAsync(ct);

            if (m.Classes is null) continue;
            var seenClasses = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var c in m.Classes)
            {
                if (string.IsNullOrWhiteSpace(c.FullName) || string.IsNullOrWhiteSpace(c.SourceFileRelativePath)) continue;
                if (!sourceFilesByPath.TryGetValue(c.SourceFileRelativePath, out var sf)) continue;
                var classKey = $"{c.FullName}|{c.SourceFileRelativePath}";
                if (!seenClasses.Add(classKey)) continue;
                db.CoverageClasses.Add(new CoverageClass
                {
                    CoverageModuleId = module.Id,
                    CoverageSourceFileId = sf.Id,
                    FullName = c.FullName,
                    SequenceCoverage = c.SequenceCoverage,
                    BranchCoverage = c.BranchCoverage,
                    CoveredSequences = c.CoveredSequences,
                    TotalSequences = c.TotalSequences,
                    CoveredBranches = c.CoveredBranches,
                    TotalBranches = c.TotalBranches,
                    VisitedLines = c.VisitedLines ?? [],
                    UnvisitedLines = c.UnvisitedLines ?? [],
                });
                classCount++;
            }
            if (m.Classes.Count > 0) await db.SaveChangesAsync(ct);
        }

        await IngestAudit.RecordAsync(audit, db, token, version.Id,
            $"coverage: {seenModules.Count} modules, {classCount} classes — {req.Project}@{req.Version}", ct);
        await db.SaveChangesAsync(ct);

        await snapshots.RecordForBuildAsync(version.Id, ct);   // TFND-176: coverage moved the score

        return Results.Ok(new CoverageIngestResponse(version.Id, report.Id, seenModules.Count, classCount, sourceFilesByPath.Count));
    }

    private static async Task<(ComponentVersion? version, IResult? error)> ResolveCvAsync(
        FindingsDbContext db, IngestToken? token, CoverageIngestRequest req, CancellationToken ct)
    {
        // Token-scoped client/project resolution; component/flavor/version
        // auto-create under that scope.
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
