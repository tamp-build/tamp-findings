using System.Xml.Linq;
using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Api.Authentication;
using Tamp.Findings.Api.Contracts;
using Tamp.Findings.Api.Ingest.Raw;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

using Tamp.Findings.Application.Auditing;

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
        app.MapPost("/ingest/test-results/raw", IngestRawAsync)
           .WithName("IngestTestResultsRaw")
           .WithSummary("Ingest a RAW test report file (.trx or JUnit XML) — POST the file body; the server parses it into the canonical model. Hierarchy comes from the query string (client, project, version required; commitSha, branch, buildId, pullRequestRef, flavor, toolVersion optional). Pass the SAME commitSha your build's other evidence uses — builds reconcile on the commit (short or full sha), so all evidence lands on one build. Requires Authorization: Bearer cli_… or prj_…")
           .Accepts<string>("application/xml", "text/xml", "application/octet-stream")
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

    private static async Task<IResult> IngestAsync(TestResultsIngestRequest req, HttpContext ctx, FindingsDbContext db, AuditLog audit, Tamp.Findings.Application.Projects.ScoreSnapshotService snapshots, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(req.Client)) return Results.BadRequest("client required");
        if (string.IsNullOrWhiteSpace(req.Project)) return Results.BadRequest("project required");
        if (string.IsNullOrWhiteSpace(req.Version)) return Results.BadRequest("version required");

        var token = IngestAuthFilter.CurrentToken(ctx);
        var (resolved, scopeErr) = await ResolveCvAsync(db, token, req, ct);
        if (scopeErr is not null) return scopeErr;
        var version = resolved!;

        // One TestRunReport per build, but ingest is replace-BY-ASSEMBLY, not replace-all. A .NET
        // solution emits one .trx per test project × TFM, so an adopter POSTs many files for one build.
        // The old replace-all (delete every prior report, insert one) meant each POST clobbered the last
        // — a silent undercount when a build has many test projects. Instead we keep the build's single
        // report and replace only the suites for the assemblies in THIS payload; suites from other files
        // stay, and the roll-up is recomputed from all of them below. The read + score paths already sum
        // across suites, so this is the only place that needed to change.
        var report = await db.TestRunReports
            .Where(r => r.ComponentVersionId == version.Id)
            .OrderBy(r => r.IngestedAt)
            .FirstOrDefaultAsync(ct);
        if (report is null)
        {
            report = new TestRunReport { ComponentVersionId = version.Id };
            db.TestRunReports.Add(report);
        }
        // Run-level metadata reflects the most recent ingest into this build.
        report.ToolName = req.ToolName;
        report.ToolVersion = req.ToolVersion;
        report.StartedAt = req.StartedAt;
        report.CompletedAt = req.CompletedAt;
        report.IngestedAt = DateTimeOffset.UtcNow;
        await db.SaveChangesAsync(ct);

        // Defensive: the old replace-all path always left ≤1 report per CV, but a mixed history could
        // have more. Collapse any extras into the one we keep so a build's suites live under one report.
        var extraIds = await db.TestRunReports
            .Where(r => r.ComponentVersionId == version.Id && r.Id != report.Id)
            .Select(r => r.Id).ToListAsync(ct);
        if (extraIds.Count > 0)
        {
            await db.TestSuiteResults.Where(s => extraIds.Contains(s.TestRunReportId))
                .ExecuteUpdateAsync(u => u.SetProperty(s => s.TestRunReportId, report.Id), ct);
            await db.TestRunReports.Where(r => extraIds.Contains(r.Id)).ExecuteDeleteAsync(ct);
        }

        // Merge suites that share an (assembly, class): a .trx can split one class across several
        // result groups, and a producer's mapper may chunk them however it likes. The sink stores
        // one row per class per assembly, so we group here rather than 500 on a duplicate — an
        // ingest must be tolerant of well-formed evidence, not brittle to how it was serialised.
        var groups = req.Suites
            .Where(s => !string.IsNullOrWhiteSpace(s.ClassName))
            .GroupBy(s => (Assembly: s.AssemblyName ?? "", s.ClassName))
            .ToList();

        // Replace only the assemblies this payload carries; leave suites from other files intact.
        var incomingAssemblies = groups.Select(g => g.Key.Assembly).Distinct().ToList();
        if (incomingAssemblies.Count > 0)
        {
            await db.TestSuiteResults
                .Where(s => s.TestRunReportId == report.Id && incomingAssemblies.Contains(s.AssemblyName))
                .ExecuteDeleteAsync(ct);   // cascades to the suites' cases
        }

        var suitesCount = 0;
        var casesCount = 0;
        foreach (var g in groups)
        {
            var suite = new TestSuiteResult
            {
                TestRunReportId = report.Id,
                AssemblyName = g.Key.Assembly,
                ClassName = g.Key.ClassName,
                TotalCount = g.Sum(s => s.TotalCount),
                PassedCount = g.Sum(s => s.PassedCount),
                FailedCount = g.Sum(s => s.FailedCount),
                SkippedCount = g.Sum(s => s.SkippedCount),
                InconclusiveCount = g.Sum(s => s.InconclusiveCount),
                DurationMs = g.Sum(s => s.DurationMs),
                Cases = g.SelectMany(s => s.Cases).Select(c => new TestCaseResult
                {
                    Name = c.Name,
                    Outcome = c.Outcome,
                    DurationMs = c.DurationMs,
                    ErrorMessage = c.ErrorMessage,
                    ErrorStackTrace = c.ErrorStackTrace,
                }).ToList(),
            };
            db.TestSuiteResults.Add(suite);
            suitesCount++;
            casesCount += suite.Cases.Count;
        }
        await db.SaveChangesAsync(ct);

        // Recompute the build's roll-up from ALL suites now under the report — this file plus any
        // sibling files already ingested — so the report totals and the gate reconcile with the tree.
        var all = await db.TestSuiteResults.AsNoTracking()
            .Where(s => s.TestRunReportId == report.Id)
            .ToListAsync(ct);
        report.TotalCount = all.Sum(s => s.TotalCount);
        report.PassedCount = all.Sum(s => s.PassedCount);
        report.FailedCount = all.Sum(s => s.FailedCount);
        report.SkippedCount = all.Sum(s => s.SkippedCount);
        report.InconclusiveCount = all.Sum(s => s.InconclusiveCount);
        report.DurationMs = all.Sum(s => s.DurationMs);
        await db.SaveChangesAsync(ct);

        await IngestAudit.RecordAsync(audit, db, token, version.Id,
            $"test-results: {suitesCount} suites, {casesCount} cases — {req.Project}@{req.Version}", ct);
        await db.SaveChangesAsync(ct);

        await snapshots.RecordForBuildAsync(version.Id, ct);   // TFND-176: tests moved the score

        return Results.Ok(new TestResultsIngestResponse(version.Id, report.Id, suitesCount, casesCount));
    }

    // Raw path: the producer POSTs the .trx / JUnit file it already has, and the sink owns the parse.
    // This kills the mapper gap — no adopter hand-rolls the trx testId join — and keeps one hardened
    // parser instead of many. It parses into the canonical request and reuses IngestAsync verbatim, so
    // storage, scoring, and audit are byte-identical to the normalized path.
    private static async Task<IResult> IngestRawAsync(
        HttpContext ctx, FindingsDbContext db, AuditLog audit,
        Tamp.Findings.Application.Projects.ScoreSnapshotService snapshots, CancellationToken ct,
        string? client, string? project, string? version,
        string? commitSha = null, string? branch = null, string? buildId = null,
        string? pullRequestRef = null, string? flavor = null, string? toolVersion = null)
    {
        if (string.IsNullOrWhiteSpace(client)) return Results.BadRequest("client required (query string)");
        if (string.IsNullOrWhiteSpace(project)) return Results.BadRequest("project required (query string)");
        if (string.IsNullOrWhiteSpace(version)) return Results.BadRequest("version required (query string)");

        XDocument doc;
        try { doc = await RawReportXml.LoadAsync(ctx.Request.Body, ct); }
        catch (RawReportXml.TooLargeException ex) { return Results.Problem(ex.Message, statusCode: StatusCodes.Status413PayloadTooLarge); }
        catch (RawReportXml.MalformedException ex) { return Results.BadRequest($"malformed report: {ex.Message}"); }

        var fmt = RawReportFormat.DetectTest(doc);
        if (fmt is null) return Results.BadRequest("unrecognised test report; expected a .trx (<TestRun>) or JUnit (<testsuites>/<testsuite>) document");

        ParsedTestResults parsed;
        try
        {
            parsed = fmt switch
            {
                RawTestFormat.Trx => TrxTestResultsParser.Parse(doc),
                _ => JUnitTestResultsParser.Parse(doc),
            };
        }
        catch (RawReportXml.MalformedException ex) { return Results.BadRequest($"malformed report: {ex.Message}"); }

        var now = DateTimeOffset.UtcNow;
        var req = new TestResultsIngestRequest(
            client!, project!, Component: null, ComponentKind: null, Flavor: flavor,
            version!, commitSha, branch, buildId, pullRequestRef,
            ToolName: parsed.ToolName, ToolVersion: toolVersion,
            TotalCount: parsed.TotalCount, PassedCount: parsed.PassedCount, FailedCount: parsed.FailedCount,
            SkippedCount: parsed.SkippedCount, InconclusiveCount: parsed.InconclusiveCount,
            DurationMs: parsed.DurationMs, StartedAt: now, CompletedAt: now,
            Suites: parsed.Suites);

        return await IngestAsync(req, ctx, db, audit, snapshots, ct);
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
        if (projectId is { } prj) q = q.Where(r => r.ComponentVersion!.ProjectId == prj);
        if (clientId is { } cli) q = q.Where(r => r.ComponentVersion!.Project!.ClientId == cli);
        if (latest)
        {
            var latestCvIds = await db.ComponentVersions
                .GroupBy(v => new { v.ProjectId, FlavorKey = v.Flavor })
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

        var version = await BuildResolver.GetOrCreateAsync(db, project!.Id, req.Flavor, req.Version,
            req.CommitSha, req.Branch, req.BuildId, req.PullRequestRef, ct);

        // TFND-165: stamp the build with the actor that produced this ingest,
        // whether it was just created or already existed.
        version.ApplyActor(req.Actor);
        await db.SaveChangesAsync(ct);
        return (version, null);
    }
}
