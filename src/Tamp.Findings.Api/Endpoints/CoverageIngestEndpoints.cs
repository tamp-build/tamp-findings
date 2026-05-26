using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Api.Authentication;
using Tamp.Findings.Api.Contracts;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;

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

    private static async Task<IResult> IngestAsync(CoverageIngestRequest req, HttpContext ctx, FindingsDbContext db, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(req.Client)) return Results.BadRequest("client required");
        if (string.IsNullOrWhiteSpace(req.Project)) return Results.BadRequest("project required");
        if (string.IsNullOrWhiteSpace(req.Component)) return Results.BadRequest("component required");
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

        return Results.Ok(new CoverageIngestResponse(version.Id, report.Id, seenModules.Count, classCount, sourceFilesByPath.Count));
    }

    private static async Task<(ComponentVersion? version, IResult? error)> ResolveCvAsync(
        FindingsDbContext db, IngestToken? token, CoverageIngestRequest req, CancellationToken ct)
    {
        // Token-scoped client/project resolution; component/flavor/version
        // auto-create under that scope.
        var (_, project, scopeErr) = await IngestScopeGuard.ResolveAndGuardAsync(db, token, req.Client, req.Project, ct);
        if (scopeErr is not null) return (null, scopeErr);

        var componentLower = req.Component.ToLower();
        var component = await db.Components.FirstOrDefaultAsync(c => c.ProjectId == project!.Id && c.Name.ToLower() == componentLower, ct)
            ?? db.Components.Add(new Component { ProjectId = project!.Id, Name = req.Component, Kind = req.ComponentKind }).Entity;
        ComponentFlavor? flavor = null;
        if (!string.IsNullOrWhiteSpace(req.Flavor))
        {
            var flavorLower = req.Flavor.ToLower();
            flavor = await db.ComponentFlavors.FirstOrDefaultAsync(f => f.ComponentId == component.Id && f.Name.ToLower() == flavorLower, ct)
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
