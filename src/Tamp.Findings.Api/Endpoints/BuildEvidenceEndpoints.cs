using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Api.Authentication;
using Tamp.Findings.Api.Contracts;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Api.Endpoints;

// TFND-265: read-back for an ingest token. Before this, a producer could write evidence but never read it: the only
// confirmation was a 200, and "did the nightly's coverage land on the right build?" needed a browser and a signed-in
// user. The same cli_/prj_ token that posted a commit's evidence now reads a summary of what the server holds for it.
//
// Scope mirrors ingest. A prj_ token reads its own project (client/project in the query are optional and, if sent, must
// name that project). A cli_ token reads any project under its client and must name the project. Anything outside the
// token's scope — another client, another project, an unknown project or commit — is a 404, never a confirmation that it
// exists. The read never creates anything: unlike ingest, a cli_ token naming an unknown project gets a 404, not a project.
public static class BuildEvidenceEndpoints
{
    public static IEndpointRouteBuilder MapBuildEvidence(this IEndpointRouteBuilder app)
    {
        app.MapGet("/ingest/builds/{commitSha}", ReadAsync)
           .WithName("ReadBuildEvidence")
           .WithTags("Ingest")
           .WithSummary(
               "Read back what the server holds for one commit, with the ingest token that posted it: the resolved build(s)"
               + " and a summary of each kind of evidence (coverage, test results, SBOM, findings by scanner, scan receipts,"
               + " quality gate, container image, analysis coverage, scan usage). Summaries only, never finding bodies or"
               + " source. commitSha may be the full sha or a 7+ character prefix. A prj_ token reads its own project;"
               + " a cli_ token must name the project (?project=). Optional ?flavor= and ?pullRequestRef= narrow to one build"
               + " context; without them every build of the commit is returned. 404 when the commit has no build the token"
               + " can see. Requires Authorization: Bearer cli_… or prj_… ingest token.")
           .Produces<BuildEvidenceResponse>(StatusCodes.Status200OK)
           .Produces(StatusCodes.Status400BadRequest)
           .Produces(StatusCodes.Status401Unauthorized)
           .Produces(StatusCodes.Status404NotFound)
           .AllowAnonymous()
           .AddEndpointFilter<IngestAuthFilter>();
        return app;
    }

    private static async Task<IResult> ReadAsync(
        string commitSha, string? client, string? project, string? flavor, string? pullRequestRef,
        HttpContext ctx, FindingsDbContext db, CancellationToken ct)
    {
        var token = IngestAuthFilter.CurrentToken(ctx);
        if (token is null) return Results.Unauthorized();

        var sha = commitSha.Trim();
        if (sha.Length < 7 || sha.Length > 64 || !sha.All(Uri.IsHexDigit))
            return Results.BadRequest("commitSha must be a hex commit sha of at least 7 characters");

        var scope = await ResolveProjectAsync(db, token, client, project, ct);
        if (scope.Error is not null) return scope.Error;
        var (projectId, clientName, projectName) = scope.Project!.Value;

        // Same matching as ingest (BuildResolver): a stored sha and the requested one are the same commit when one is a
        // 7+ char prefix of the other. The LIKE on the first 7 chars narrows in the database; the exact rule runs here.
        var head = sha[..7].ToLowerInvariant();
        var flavorLower = string.IsNullOrWhiteSpace(flavor) ? null : flavor.Trim().ToLower();
        var pr = string.IsNullOrWhiteSpace(pullRequestRef) ? null : pullRequestRef.Trim();
        var candidates = await db.ComponentVersions.AsNoTracking()
            .Where(v => v.ProjectId == projectId && v.CommitSha != null && v.CommitSha.ToLower().StartsWith(head))
            .Where(v => flavorLower == null || (v.Flavor != null && v.Flavor.ToLower() == flavorLower))
            .Where(v => pr == null || v.PullRequestRef == pr)
            .OrderBy(v => v.CreatedAt)
            .ToListAsync(ct);
        var builds = candidates.Where(v => BuildResolver.ShaIdentifiesSameCommit(v.CommitSha!, sha)).ToList();
        if (builds.Count == 0) return Results.NotFound("no build for this commit in the token's scope");

        var evidence = new List<BuildEvidence>(builds.Count);
        foreach (var b in builds) evidence.Add(await EvidenceForAsync(db, b, ct));

        return Results.Ok(new BuildEvidenceResponse(projectId, clientName, projectName, sha, evidence));
    }

    private readonly record struct ProjectScope(
        (Guid Id, string Client, string Project)? Project, IResult? Error);

    private static async Task<ProjectScope> ResolveProjectAsync(
        FindingsDbContext db, IngestToken token, string? clientName, string? projectName, CancellationToken ct)
    {
        var notFound = new ProjectScope(null, Results.NotFound("project not found"));
        var q = db.Projects.AsNoTracking().Join(db.Clients.AsNoTracking(), p => p.ClientId, c => c.Id,
            (p, c) => new { p.Id, p.Name, p.ClientId, ClientName = c.Name });

        if (token.Scope == IngestTokenScope.Project)
        {
            var own = await q.FirstOrDefaultAsync(p => p.Id == token.ProjectId, ct);
            if (own is null) return notFound;
            // Names are optional with a prj_ token; when sent they must agree with it (case-insensitively, as ingest).
            if (!string.IsNullOrWhiteSpace(clientName) && !own.ClientName.Equals(clientName.Trim(), StringComparison.OrdinalIgnoreCase))
                return notFound;
            if (!string.IsNullOrWhiteSpace(projectName) && !own.Name.Equals(projectName.Trim(), StringComparison.OrdinalIgnoreCase))
                return notFound;
            return new ProjectScope((own.Id, own.ClientName, own.Name), null);
        }

        if (string.IsNullOrWhiteSpace(projectName))
            return new ProjectScope(null, Results.BadRequest("project required: a cli_ token covers every project under its client"));

        var projectLower = projectName.Trim().ToLower();
        var match = await q.FirstOrDefaultAsync(p => p.ClientId == token.ClientId && p.Name.ToLower() == projectLower, ct);
        if (match is null) return notFound;
        if (!string.IsNullOrWhiteSpace(clientName) && !match.ClientName.Equals(clientName.Trim(), StringComparison.OrdinalIgnoreCase))
            return notFound;
        return new ProjectScope((match.Id, match.ClientName, match.Name), null);
    }

    private static async Task<BuildEvidence> EvidenceForAsync(FindingsDbContext db, ComponentVersion b, CancellationToken ct)
    {
        var id = b.Id;

        CoverageEvidence? coverage = null;
        var cov = await db.CoverageReports.AsNoTracking().Where(r => r.ComponentVersionId == id)
            .OrderByDescending(r => r.IngestedAt).FirstOrDefaultAsync(ct);
        if (cov is not null)
        {
            var modules = await db.CoverageModules.CountAsync(m => m.CoverageReportId == cov.Id, ct);
            var files = await db.CoverageSourceFiles.CountAsync(f => f.CoverageReportId == cov.Id, ct);
            var classes = await db.CoverageClasses.CountAsync(
                c => db.CoverageModules.Any(m => m.Id == c.CoverageModuleId && m.CoverageReportId == cov.Id), ct);
            coverage = new CoverageEvidence(cov.ToolName, cov.ToolVersion, cov.SequenceCoverage, cov.BranchCoverage,
                cov.CoveredSequences, cov.TotalSequences, cov.CoveredBranches, cov.TotalBranches,
                modules, files, classes, cov.IngestedAt);
        }

        TestResultsEvidence? tests = null;
        var run = await db.TestRunReports.AsNoTracking().Where(r => r.ComponentVersionId == id)
            .OrderByDescending(r => r.IngestedAt).FirstOrDefaultAsync(ct);
        if (run is not null)
        {
            var suites = await db.TestSuiteResults.CountAsync(s => s.TestRunReportId == run.Id, ct);
            var cases = await db.TestCaseResults.CountAsync(
                c => db.TestSuiteResults.Any(s => s.Id == c.TestSuiteResultId && s.TestRunReportId == run.Id), ct);
            tests = new TestResultsEvidence(run.ToolName, run.ToolVersion, run.TotalCount, run.PassedCount,
                run.FailedCount, run.SkippedCount, run.InconclusiveCount, suites, cases, run.CompletedAt, run.IngestedAt);
        }

        SbomEvidence? sbom = null;
        var snap = await db.SbomSnapshots.AsNoTracking().Where(s => s.ComponentVersionId == id)
            .OrderByDescending(s => s.IngestedAt).FirstOrDefaultAsync(ct);
        if (snap is not null)
        {
            var components = await db.SbomComponents.CountAsync(c => c.SbomSnapshotId == snap.Id, ct);
            var vulns = await db.Vulnerabilities.CountAsync(
                v => db.SbomComponents.Any(c => c.Id == v.SbomComponentId && c.SbomSnapshotId == snap.Id), ct);
            sbom = new SbomEvidence(snap.Id, snap.ToolName, snap.ToolVersion, snap.SpecVersion, snap.SerialNumber,
                components, vulns, snap.ProvenanceType, snap.ProvenanceVerified, snap.IngestedAt);
        }

        var findingRows = await db.Findings.AsNoTracking().Where(f => f.ComponentVersionId == id)
            .GroupBy(f => new { f.Scanner, f.Status, f.Severity })
            .Select(g => new { g.Key.Scanner, g.Key.Status, g.Key.Severity, Count = g.Count() })
            .ToListAsync(ct);
        var findings = findingRows
            .GroupBy(r => r.Scanner)
            .OrderBy(g => g.Key.ToString(), StringComparer.Ordinal)
            .Select(g => new ScannerFindingsEvidence(
                g.Key.ToString(),
                g.Sum(r => r.Count),
                g.Where(r => r.Status == FindingStatus.Open).Sum(r => r.Count),
                g.Where(r => r.Status == FindingStatus.Open)
                    .GroupBy(r => r.Severity)
                    .OrderByDescending(s => s.Key)
                    .ToDictionary(s => s.Key.ToString(), s => s.Sum(r => r.Count))))
            .ToList();

        var scanRuns = (await db.ScanRunReceipts.AsNoTracking().Where(r => r.ComponentVersionId == id).ToListAsync(ct))
            .OrderBy(r => r.Scanner.ToString(), StringComparer.Ordinal)
            .Select(r => new ScanRunEvidence(r.Scanner.ToString(), r.Status.ToString(), r.FindingsCount,
                r.ToolName, r.ToolVersion, r.CompletedAt, r.IngestedAt))
            .ToList();

        var gate = await db.QualityGateResults.AsNoTracking().Where(r => r.ComponentVersionId == id)
            .OrderByDescending(r => r.IngestedAt)
            .Select(r => new QualityGateEvidence(r.Status, r.Source, r.AnalysisId, r.ObservedAt, r.IngestedAt))
            .FirstOrDefaultAsync(ct);

        var image = await db.ContainerImages.AsNoTracking().Where(i => i.ComponentVersionId == id)
            .OrderByDescending(i => i.InspectedAt)
            .Select(i => new ContainerImageEvidence(i.Reference, i.Digest, i.BaseImageReference, i.BaseImageDigest, i.InspectedAt))
            .FirstOrDefaultAsync(ct);

        AnalysisCoverageEvidence? analysis = null;
        var ac = await db.AnalysisCoverageReports.AsNoTracking().Where(r => r.ComponentVersionId == id)
            .OrderByDescending(r => r.IngestedAt).FirstOrDefaultAsync(ct);
        if (ac is not null)
            analysis = new AnalysisCoverageEvidence(
                await db.AnalysisCoverageLanguages.CountAsync(l => l.AnalysisCoverageReportId == ac.Id, ct),
                ac.GapLanguages, ac.ObservedAt, ac.IngestedAt);

        var usage = await db.ScanUsageObservations.AsNoTracking().Where(o => o.ComponentVersionId == id)
            .GroupBy(_ => 1)
            .Select(g => new ScanUsageEvidence(g.Count(), g.Sum(o => o.InputTokens), g.Sum(o => o.OutputTokens)))
            .FirstOrDefaultAsync(ct);

        var conformance = await db.ConformanceFindings.CountAsync(c => c.ComponentVersionId == id, ct);
        var diagnostics = await db.DecisionDiagnostics.CountAsync(d => d.ComponentVersionId == id, ct);

        return new BuildEvidence(ResolvedBuild.From(b), coverage, tests, sbom, findings, scanRuns, gate, image,
            analysis, usage, conformance, diagnostics);
    }
}
