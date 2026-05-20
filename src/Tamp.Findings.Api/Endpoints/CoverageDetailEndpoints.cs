using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Api.Contracts;
using Tamp.Findings.Data;

namespace Tamp.Findings.Api.Endpoints;

// Read endpoints powering the coverage detail view. Scope filters mirror
// /aggregates so the same hierarchy selector on the SPA controls both.
//   GET /coverage/tree      — module→class summaries (light payload)
//   GET /coverage/class/{id} — full source + line maps (heavier)
public static class CoverageDetailEndpoints
{
    public static IEndpointRouteBuilder MapCoverageDetail(this IEndpointRouteBuilder app)
    {
        app.MapGet("/coverage/tree", GetTreeAsync)
           .WithName("GetCoverageTree")
           .WithSummary("Coverage tree rolled up across scope. Returns module → class tree with summary counts; source text and line maps live on /coverage/class/{id}.");
        app.MapGet("/coverage/class/{id:guid}", GetClassAsync)
           .WithName("GetCoverageClassDetail")
           .WithSummary("Single class detail with source text and visited/unvisited line arrays for the line-tinted source viewer.");
        return app;
    }

    private static async Task<IResult> GetTreeAsync(
        FindingsDbContext db,
        CancellationToken ct,
        Guid? clientId = null,
        Guid? projectId = null,
        Guid? componentId = null)
    {
        var reports = await ScopedReportsAsync(db, clientId, projectId, componentId, ct);
        if (reports.Count == 0)
        {
            return Results.Ok(new CoverageTreeResponse(
                Measured: false,
                SequenceCoverage: null,
                BranchCoverage: null,
                CoveredSequences: 0,
                TotalSequences: 0,
                Modules: []));
        }

        var reportIds = reports.Select(r => r.Id).ToList();

        // Fold modules across all reports in scope by name; a module appearing
        // in multiple component versions sums into one row. Same idea for
        // classes within a module (folded on FullName+SourceFile).
        var modules = await db.CoverageModules
            .AsNoTracking()
            .Where(m => reportIds.Contains(m.CoverageReportId))
            .Include(m => m.Classes!).ThenInclude(c => c.SourceFile)
            .ToListAsync(ct);

        var moduleGroups = modules
            .GroupBy(m => m.Name, StringComparer.OrdinalIgnoreCase)
            .Select(g =>
            {
                var classGroups = g.SelectMany(m => m.Classes)
                    .GroupBy(c => new { c.FullName, c.SourceFile!.RelativePath })
                    .Select(cg =>
                    {
                        // When a class appears in N reports in scope, pick the
                        // newest by SourceFile.Id (a proxy for "most recently
                        // ingested") to back the click-through. Counts are
                        // summed across reports for the tree row, but the
                        // canonical class detail is one row.
                        var representative = cg.OrderByDescending(c => c.SourceFile!.Id).First();
                        var coveredSum = cg.Sum(c => c.CoveredSequences);
                        var totalSum = cg.Sum(c => c.TotalSequences);
                        return new CoverageTreeClassDto(
                            Id: representative.Id,
                            FullName: cg.Key.FullName,
                            SourceFileRelativePath: cg.Key.RelativePath,
                            SequenceCoverage: totalSum == 0 ? 0 : 100.0 * coveredSum / totalSum,
                            CoveredSequences: coveredSum,
                            TotalSequences: totalSum);
                    })
                    .OrderBy(c => c.FullName, StringComparer.OrdinalIgnoreCase)
                    .ToList();

                var covered = g.Sum(m => m.CoveredSequences);
                var total = g.Sum(m => m.TotalSequences);
                return new CoverageTreeModuleDto(
                    Name: g.Key,
                    SequenceCoverage: total == 0 ? 0 : 100.0 * covered / total,
                    BranchCoverage: 0,  // module-level branch coverage not folded — class-level lines are the meaningful drill axis
                    CoveredSequences: covered,
                    TotalSequences: total,
                    Classes: classGroups);
            })
            .OrderBy(m => m.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var reportCovered = reports.Sum(r => r.CoveredSequences);
        var reportTotal = reports.Sum(r => r.TotalSequences);

        return Results.Ok(new CoverageTreeResponse(
            Measured: true,
            SequenceCoverage: reportTotal == 0 ? 0 : 100.0 * reportCovered / reportTotal,
            BranchCoverage: reports.Sum(r => r.TotalBranches) == 0 ? 0 : 100.0 * reports.Sum(r => r.CoveredBranches) / reports.Sum(r => r.TotalBranches),
            CoveredSequences: reportCovered,
            TotalSequences: reportTotal,
            Modules: moduleGroups));
    }

    private static async Task<IResult> GetClassAsync(Guid id, FindingsDbContext db, CancellationToken ct)
    {
        var cls = await db.CoverageClasses
            .AsNoTracking()
            .Where(c => c.Id == id)
            .Include(c => c.Module)
            .Include(c => c.SourceFile)
            .FirstOrDefaultAsync(ct);
        if (cls is null) return Results.NotFound();
        return Results.Ok(new CoverageClassDetailResponse(
            Id: cls.Id,
            ModuleName: cls.Module?.Name ?? "",
            FullName: cls.FullName,
            SourceFileRelativePath: cls.SourceFile?.RelativePath ?? "",
            SequenceCoverage: cls.SequenceCoverage,
            BranchCoverage: cls.BranchCoverage,
            CoveredSequences: cls.CoveredSequences,
            TotalSequences: cls.TotalSequences,
            CoveredBranches: cls.CoveredBranches,
            TotalBranches: cls.TotalBranches,
            VisitedLines: cls.VisitedLines,
            UnvisitedLines: cls.UnvisitedLines,
            SourceText: cls.SourceFile?.SourceText ?? ""));
    }

    private static async Task<List<Domain.Entities.CoverageReport>> ScopedReportsAsync(
        FindingsDbContext db,
        Guid? clientId,
        Guid? projectId,
        Guid? componentId,
        CancellationToken ct)
    {
        // Same latest-CV rule as /aggregates: the dashboard never accumulates
        // coverage across historical builds. Each Component+Flavor's most
        // recent ComponentVersion contributes its single report (if any).
        var latestCvIds = await db.ComponentVersions
            .GroupBy(v => new { v.ComponentId, FlavorKey = v.FlavorId ?? Guid.Empty })
            .Select(g => g.OrderByDescending(v => v.CreatedAt).First().Id)
            .ToListAsync(ct);

        var q = db.CoverageReports.AsNoTracking()
            .Where(r => latestCvIds.Contains(r.ComponentVersionId));
        if (componentId is { } cmp)
            q = q.Where(r => r.ComponentVersion!.ComponentId == cmp);
        if (projectId is { } prj)
            q = q.Where(r => r.ComponentVersion!.Component!.ProjectId == prj);
        if (clientId is { } cli)
            q = q.Where(r => r.ComponentVersion!.Component!.Project!.ClientId == cli);
        return await q.ToListAsync(ct);
    }
}
