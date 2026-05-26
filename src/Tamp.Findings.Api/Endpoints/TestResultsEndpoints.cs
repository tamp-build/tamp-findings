using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Api.Authentication;
using Tamp.Findings.Api.Contracts;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Api.Endpoints;

// TFND-20: TRX-style test results.
//   POST /ingest/test-results          — replace-on-ingest per CV
//   GET  /test-results/tree            — assembly → class tree for Tests tab
//   GET  /test-results/suite/{id}      — full case list for a suite
public static class TestResultsEndpoints
{
    public static IEndpointRouteBuilder MapTestResults(this IEndpointRouteBuilder app)
    {
        app.MapPost("/ingest/test-results", IngestAsync)
           .WithName("IngestTestResults")
           .WithSummary("Replace-on-ingest test run results. Suites + cases under one TestRunReport per ComponentVersion. Requires Authorization: Bearer cli_… or prj_…")
           .AllowAnonymous()
           .AddEndpointFilter<IngestAuthFilter>();
        app.MapGet("/test-results/tree", GetTreeAsync)
           .WithName("GetTestResultsTree")
           .WithSummary("Assembly → class tree powering the Tests tab. Same scope filters as /aggregates.");
        app.MapGet("/test-results/suite/{id:guid}", GetSuiteAsync)
           .WithName("GetTestResultsSuite")
           .WithSummary("All test cases on one suite (test class), including error messages + stack traces for failed cases.");
        return app;
    }

    private static async Task<IResult> IngestAsync(TestResultsIngestRequest req, HttpContext ctx, FindingsDbContext db, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(req.Client)) return Results.BadRequest("client required");
        if (string.IsNullOrWhiteSpace(req.Project)) return Results.BadRequest("project required");
        if (string.IsNullOrWhiteSpace(req.Component)) return Results.BadRequest("component required");
        if (string.IsNullOrWhiteSpace(req.Version)) return Results.BadRequest("version required");

        var token = IngestAuthFilter.CurrentToken(ctx);
        var (resolved, scopeErr) = await ResolveCvAsync(db, token, req, ct);
        if (scopeErr is not null) return scopeErr;
        var version = resolved!;

        // Replace-on-ingest, same shape as CoverageReport.
        var existing = await db.TestRunReports
            .Where(r => r.ComponentVersionId == version.Id)
            .ToListAsync(ct);
        if (existing.Count > 0)
        {
            db.TestRunReports.RemoveRange(existing);
            await db.SaveChangesAsync(ct);
        }

        var report = new TestRunReport
        {
            ComponentVersionId = version.Id,
            ToolName = req.ToolName,
            ToolVersion = req.ToolVersion,
            TotalCount = req.TotalCount,
            PassedCount = req.PassedCount,
            FailedCount = req.FailedCount,
            SkippedCount = req.SkippedCount,
            InconclusiveCount = req.InconclusiveCount,
            DurationMs = req.DurationMs,
            StartedAt = req.StartedAt,
            CompletedAt = req.CompletedAt,
        };
        db.TestRunReports.Add(report);
        await db.SaveChangesAsync(ct);

        var suitesCount = 0;
        var casesCount = 0;
        foreach (var s in req.Suites)
        {
            if (string.IsNullOrWhiteSpace(s.ClassName)) continue;
            var suite = new TestSuiteResult
            {
                TestRunReportId = report.Id,
                AssemblyName = s.AssemblyName,
                ClassName = s.ClassName,
                TotalCount = s.TotalCount,
                PassedCount = s.PassedCount,
                FailedCount = s.FailedCount,
                SkippedCount = s.SkippedCount,
                InconclusiveCount = s.InconclusiveCount,
                DurationMs = s.DurationMs,
            };
            db.TestSuiteResults.Add(suite);
            await db.SaveChangesAsync(ct);
            suitesCount++;

            foreach (var c in s.Cases)
            {
                db.TestCaseResults.Add(new TestCaseResult
                {
                    TestSuiteResultId = suite.Id,
                    Name = c.Name,
                    Outcome = c.Outcome,
                    DurationMs = c.DurationMs,
                    ErrorMessage = c.ErrorMessage,
                    ErrorStackTrace = c.ErrorStackTrace,
                });
                casesCount++;
            }
            if (s.Cases.Count > 0) await db.SaveChangesAsync(ct);
        }

        return Results.Ok(new TestResultsIngestResponse(version.Id, report.Id, suitesCount, casesCount));
    }

    private static async Task<IResult> GetTreeAsync(
        FindingsDbContext db,
        CancellationToken ct,
        Guid? clientId = null,
        Guid? projectId = null,
        Guid? componentId = null,
        bool latest = true)
    {
        var reports = await ScopedReportsAsync(db, clientId, projectId, componentId, latest, ct);
        if (reports.Count == 0)
        {
            return Results.Ok(new TestResultsTreeResponse(
                Measured: false,
                TotalCount: 0, PassedCount: 0, FailedCount: 0, SkippedCount: 0, InconclusiveCount: 0,
                DurationMs: 0, CompletedAt: null,
                Assemblies: []));
        }

        var reportIds = reports.Select(r => r.Id).ToList();
        var suites = await db.TestSuiteResults.AsNoTracking()
            .Where(s => reportIds.Contains(s.TestRunReportId))
            .ToListAsync(ct);

        var assemblies = suites
            .GroupBy(s => s.AssemblyName, StringComparer.OrdinalIgnoreCase)
            .Select(g => new TestTreeAssemblyDto(
                Name: g.Key,
                TotalCount: g.Sum(s => s.TotalCount),
                PassedCount: g.Sum(s => s.PassedCount),
                FailedCount: g.Sum(s => s.FailedCount),
                SkippedCount: g.Sum(s => s.SkippedCount),
                Suites: g
                    .OrderByDescending(s => s.FailedCount)
                    .ThenBy(s => s.ClassName, StringComparer.OrdinalIgnoreCase)
                    .Select(s => new TestTreeSuiteDto(
                        Id: s.Id,
                        ClassName: s.ClassName,
                        TotalCount: s.TotalCount,
                        PassedCount: s.PassedCount,
                        FailedCount: s.FailedCount,
                        SkippedCount: s.SkippedCount))
                    .ToList()))
            .OrderByDescending(a => a.FailedCount)
            .ThenBy(a => a.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();

        return Results.Ok(new TestResultsTreeResponse(
            Measured: true,
            TotalCount: reports.Sum(r => r.TotalCount),
            PassedCount: reports.Sum(r => r.PassedCount),
            FailedCount: reports.Sum(r => r.FailedCount),
            SkippedCount: reports.Sum(r => r.SkippedCount),
            InconclusiveCount: reports.Sum(r => r.InconclusiveCount),
            DurationMs: reports.Sum(r => r.DurationMs),
            CompletedAt: reports.Max(r => r.CompletedAt),
            Assemblies: assemblies));
    }

    private static async Task<IResult> GetSuiteAsync(Guid id, FindingsDbContext db, CancellationToken ct)
    {
        var suite = await db.TestSuiteResults.AsNoTracking()
            .Where(s => s.Id == id)
            .Include(s => s.Cases)
            .FirstOrDefaultAsync(ct);
        if (suite is null) return Results.NotFound();
        return Results.Ok(new TestSuiteDetailResponse(
            Id: suite.Id,
            AssemblyName: suite.AssemblyName,
            ClassName: suite.ClassName,
            TotalCount: suite.TotalCount,
            PassedCount: suite.PassedCount,
            FailedCount: suite.FailedCount,
            SkippedCount: suite.SkippedCount,
            DurationMs: suite.DurationMs,
            Cases: suite.Cases
                .OrderByDescending(c => c.Outcome == TestOutcome.Failed)
                .ThenBy(c => c.Name, StringComparer.OrdinalIgnoreCase)
                .Select(c => new TestCaseDetailDto(c.Name, c.Outcome, c.DurationMs, c.ErrorMessage, c.ErrorStackTrace))
                .ToList()));
    }

    private static async Task<List<TestRunReport>> ScopedReportsAsync(
        FindingsDbContext db,
        Guid? clientId,
        Guid? projectId,
        Guid? componentId,
        bool latest,
        CancellationToken ct)
    {
        var q = db.TestRunReports.AsNoTracking().AsQueryable();
        if (componentId is { } cmp) q = q.Where(r => r.ComponentVersion!.ComponentId == cmp);
        if (projectId is { } prj) q = q.Where(r => r.ComponentVersion!.Component!.ProjectId == prj);
        if (clientId is { } cli) q = q.Where(r => r.ComponentVersion!.Component!.Project!.ClientId == cli);
        if (latest)
        {
            var latestCvIds = await db.ComponentVersions
                .GroupBy(v => new { v.ComponentId, FlavorKey = v.FlavorId ?? Guid.Empty })
                .Select(g => g.OrderByDescending(v => v.CreatedAt).First().Id)
                .ToListAsync(ct);
            q = q.Where(r => latestCvIds.Contains(r.ComponentVersionId));
        }
        return await q.ToListAsync(ct);
    }

    private static async Task<(ComponentVersion? version, IResult? error)> ResolveCvAsync(
        FindingsDbContext db, IngestToken? token, TestResultsIngestRequest req, CancellationToken ct)
    {
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
