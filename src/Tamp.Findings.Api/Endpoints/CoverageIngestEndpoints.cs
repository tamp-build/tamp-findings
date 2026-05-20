using Microsoft.EntityFrameworkCore;
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
           .WithSummary("Replace the coverage report for one component version. Replace-on-ingest: any prior report for the same CV is deleted before insert.");
        return app;
    }

    private static async Task<IResult> IngestAsync(CoverageIngestRequest req, FindingsDbContext db, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(req.Client)) return Results.BadRequest("client required");
        if (string.IsNullOrWhiteSpace(req.Project)) return Results.BadRequest("project required");
        if (string.IsNullOrWhiteSpace(req.Component)) return Results.BadRequest("component required");
        if (string.IsNullOrWhiteSpace(req.Version)) return Results.BadRequest("version required");

        var version = await ResolveCvAsync(db, req, ct);

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

        // Modules deduped on name (some tools emit duplicates for re-instrumented builds).
        var seenModules = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var m in req.Modules)
        {
            if (string.IsNullOrWhiteSpace(m.Name)) continue;
            if (!seenModules.Add(m.Name)) continue;
            db.CoverageModules.Add(new CoverageModule
            {
                CoverageReportId = report.Id,
                Name = m.Name,
                SequenceCoverage = m.SequenceCoverage,
                BranchCoverage = m.BranchCoverage,
                CoveredSequences = m.CoveredSequences,
                TotalSequences = m.TotalSequences,
            });
        }
        await db.SaveChangesAsync(ct);

        return Results.Ok(new CoverageIngestResponse(version.Id, report.Id, seenModules.Count));
    }

    private static async Task<ComponentVersion> ResolveCvAsync(FindingsDbContext db, CoverageIngestRequest req, CancellationToken ct)
    {
        // Same find-or-create chain as SBOM/ingest/findings — keeps the
        // entity tree consistent regardless of which producer ingests first.
        var client = await db.Clients.FirstOrDefaultAsync(c => c.Name == req.Client, ct)
            ?? db.Clients.Add(new Client { Name = req.Client }).Entity;
        var project = await db.Projects.FirstOrDefaultAsync(p => p.ClientId == client.Id && p.Name == req.Project, ct)
            ?? db.Projects.Add(new Project { ClientId = client.Id, Name = req.Project }).Entity;
        var component = await db.Components.FirstOrDefaultAsync(c => c.ProjectId == project.Id && c.Name == req.Component, ct)
            ?? db.Components.Add(new Component { ProjectId = project.Id, Name = req.Component, Kind = req.ComponentKind }).Entity;
        ComponentFlavor? flavor = null;
        if (!string.IsNullOrWhiteSpace(req.Flavor))
        {
            flavor = await db.ComponentFlavors.FirstOrDefaultAsync(f => f.ComponentId == component.Id && f.Name == req.Flavor, ct)
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
        return version;
    }
}
