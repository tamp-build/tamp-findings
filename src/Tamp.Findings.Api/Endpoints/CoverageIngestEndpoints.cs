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

public static class CoverageIngestEndpoints
{
    public static IEndpointRouteBuilder MapCoverageIngest(this IEndpointRouteBuilder app)
    {
        app.MapPost("/ingest/coverage", IngestAsync)
           .WithName("IngestCoverage")
           .WithSummary("Replace the coverage report for one component version. Replace-on-ingest: any prior report for the same CV is deleted before insert. Requires Authorization: Bearer cli_… or prj_…")
           .AllowAnonymous()
           .AddEndpointFilter<IngestAuthFilter>();
        app.MapPost("/ingest/coverage/raw", IngestRawAsync)
           .WithName("IngestCoverageRaw")
           .WithSummary("Ingest a RAW coverage report file (Cobertura or OpenCover XML) — POST the file body; the server parses it into overall + per-module coverage. Line-level overlay is not produced on this path (raw reports carry no source text) — use /ingest/coverage for that. Hierarchy comes from the query string (client, project, version required; commitSha, branch, buildId, pullRequestRef, flavor, toolVersion optional). Pass the SAME commitSha your build's other evidence uses — builds reconcile on the commit (short or full sha), so all evidence lands on one build. Requires Authorization: Bearer cli_… or prj_…")
           .Accepts<string>("application/xml", "text/xml", "application/octet-stream")
           .AllowAnonymous()
           .AddEndpointFilter<IngestAuthFilter>();
        return app;
    }

    private static Task<IResult> IngestAsync(CoverageIngestRequest req, HttpContext ctx, FindingsDbContext db, AuditLog audit, Tamp.Findings.Application.Projects.ScoreSnapshotService snapshots, CancellationToken ct)
        => IngestCoreAsync(req, ctx, db, audit, snapshots, raw: null, rawFormat: null, rawFileName: null, ct);

    private static async Task<IResult> IngestCoreAsync(CoverageIngestRequest req, HttpContext ctx, FindingsDbContext db, AuditLog audit, Tamp.Findings.Application.Projects.ScoreSnapshotService snapshots, byte[]? raw, string? rawFormat, string? rawFileName, CancellationToken ct)
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

        // Keep the raw file as evidence of record (TFND-209) — only the raw endpoint supplies it.
        if (raw is not null)
        {
            await RawArtifactStore.UpsertAsync(db, version.Id, RawArtifactKind.Coverage, rawFormat ?? "", rawFileName, req.ToolName, raw, ct);
            await db.SaveChangesAsync(ct);
        }

        await IngestAudit.RecordAsync(audit, db, token, version.Id,
            $"coverage: {seenModules.Count} modules, {classCount} classes — {req.Project}@{req.Version}", ct);
        await db.SaveChangesAsync(ct);

        await snapshots.RecordForBuildAsync(version.Id, ct);   // TFND-176: coverage moved the score

        return Results.Ok(new CoverageIngestResponse(version.Id, report.Id, seenModules.Count, classCount, sourceFilesByPath.Count));
    }

    // Raw path: POST the cobertura/opencover file the CI run already produced; the sink parses it into
    // overall + per-module coverage and reuses IngestAsync. Line-level classes are omitted here (raw
    // reports have no source text), which is enough for the score and the coverageFloor gate.
    private static async Task<IResult> IngestRawAsync(
        HttpContext ctx, FindingsDbContext db, AuditLog audit,
        Tamp.Findings.Application.Projects.ScoreSnapshotService snapshots, CancellationToken ct,
        string? client, string? project, string? version,
        string? commitSha = null, string? branch = null, string? buildId = null,
        string? pullRequestRef = null, string? flavor = null, string? toolVersion = null, string? filename = null)
    {
        if (string.IsNullOrWhiteSpace(client)) return Results.BadRequest("client required (query string)");
        if (string.IsNullOrWhiteSpace(project)) return Results.BadRequest("project required (query string)");
        if (string.IsNullOrWhiteSpace(version)) return Results.BadRequest("version required (query string)");

        RawReportXml.Loaded loaded;
        try { loaded = await RawReportXml.LoadWithBytesAsync(ctx.Request.Body, ct); }
        catch (RawReportXml.TooLargeException ex) { return Results.Problem(ex.Message, statusCode: StatusCodes.Status413PayloadTooLarge); }
        catch (RawReportXml.MalformedException ex) { return Results.BadRequest($"malformed report: {ex.Message}"); }

        var fmt = RawReportFormat.DetectCoverage(loaded.Doc);
        if (fmt is null) return Results.BadRequest("unrecognised coverage report; expected Cobertura (<coverage>) or OpenCover (<CoverageSession>) XML");

        ParsedCoverage parsed;
        try
        {
            parsed = fmt switch
            {
                RawCoverageFormat.Cobertura => CoberturaCoverageParser.Parse(loaded.Doc),
                _ => OpenCoverCoverageParser.Parse(loaded.Doc),
            };
        }
        catch (RawReportXml.MalformedException ex) { return Results.BadRequest($"malformed report: {ex.Message}"); }

        var req = new CoverageIngestRequest(
            client!, project!, Component: null, ComponentKind: null, Flavor: flavor,
            version!, commitSha, branch, buildId, pullRequestRef,
            ToolName: parsed.ToolName, ToolVersion: toolVersion,
            SequenceCoverage: parsed.SequenceCoverage, BranchCoverage: parsed.BranchCoverage,
            CoveredSequences: parsed.CoveredSequences, TotalSequences: parsed.TotalSequences,
            CoveredBranches: parsed.CoveredBranches, TotalBranches: parsed.TotalBranches,
            Modules: parsed.Modules, SourceFiles: parsed.SourceFiles);

        var format = fmt == RawCoverageFormat.Cobertura ? "cobertura" : "opencover";
        return await IngestCoreAsync(req, ctx, db, audit, snapshots, loaded.Raw, format, filename, ct);
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
