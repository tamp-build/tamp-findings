using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Api.Contracts;
using Tamp.Findings.Data;

namespace Tamp.Findings.Api.Endpoints;

public static class SbomComponentsEndpoints
{
    public static IEndpointRouteBuilder MapSbomComponents(this IEndpointRouteBuilder app)
    {
        app.MapGet("/sbom-components", ListAsync)
           .WithName("ListSbomComponents")
           .WithSummary("Cross-version SBOM components with ecosystem filter, paging, and vuln counts");

        app.MapGet("/sbom-components/{id:guid}", DetailAsync)
           .WithName("GetSbomComponent")
           .WithSummary("Single SBOM component with full vulnerability list and dependency edges");

        return app;
    }

    private static string EcosystemFromPurl(string purl)
    {
        if (string.IsNullOrEmpty(purl) || !purl.StartsWith("pkg:")) return "unknown";
        var slash = purl.IndexOf('/', 4);
        return slash > 4 ? purl[4..slash] : "unknown";
    }

    private static async Task<Ok<SbomComponentsListResponse>> ListAsync(
        FindingsDbContext db,
        CancellationToken ct,
        Guid? componentVersionId = null,
        Guid? clientId = null,
        Guid? projectId = null,
        string? ecosystem = null,
        string? search = null,
        int skip = 0,
        int take = 100)
    {
        take = Math.Clamp(take, 1, 500);
        skip = Math.Max(skip, 0);

        var q = db.SbomComponents
            .Include(c => c.SbomSnapshot)!.ThenInclude(s => s!.ComponentVersion)!.ThenInclude(v => v!.Component)!.ThenInclude(c => c!.Project)!.ThenInclude(p => p!.Client)
            .AsNoTracking();

        if (componentVersionId is { } cv) q = q.Where(c => c.SbomSnapshot!.ComponentVersionId == cv);
        if (projectId is { } prj) q = q.Where(c => c.SbomSnapshot!.ComponentVersion!.Component!.ProjectId == prj);
        if (clientId is { } cli) q = q.Where(c => c.SbomSnapshot!.ComponentVersion!.Component!.Project!.ClientId == cli);

        // Filter by ecosystem via PURL prefix. Done in-DB so paging is honest.
        if (!string.IsNullOrWhiteSpace(ecosystem))
        {
            var eco = ecosystem.Trim();
            q = q.Where(c => c.Purl.StartsWith($"pkg:{eco}/"));
        }

        if (!string.IsNullOrWhiteSpace(search))
        {
            var s = search.Trim();
            q = q.Where(c => EF.Functions.ILike(c.Name, $"%{s}%") || EF.Functions.ILike(c.Purl, $"%{s}%"));
        }

        var total = await q.CountAsync(ct);

        // Compute ecosystem counts and total vulns over the filtered set
        // (helps the SPA show meaningful aggregates even when paged).
        var ecoCountsRaw = await q
            .GroupBy(c => c.Purl.StartsWith("pkg:nuget/") ? "nuget"
                          : c.Purl.StartsWith("pkg:npm/") ? "npm"
                          : "other")
            .Select(g => new { Eco = g.Key, Count = g.Count() })
            .ToListAsync(ct);
        var nugetCount = ecoCountsRaw.FirstOrDefault(e => e.Eco == "nuget")?.Count ?? 0;
        var npmCount = ecoCountsRaw.FirstOrDefault(e => e.Eco == "npm")?.Count ?? 0;
        var otherCount = ecoCountsRaw.FirstOrDefault(e => e.Eco == "other")?.Count ?? 0;

        var totalVulns = await q.SelectMany(c => c.Vulnerabilities).CountAsync(ct);

        var rows = await q
            .OrderBy(c => c.Name)
            .ThenBy(c => c.Version)
            .Skip(skip)
            .Take(take)
            .Select(c => new SbomComponentListItem(
                c.Id,
                c.Purl,
                c.Name,
                c.Version,
                c.Kind,
                c.Purl.StartsWith("pkg:nuget/") ? "nuget"
                  : c.Purl.StartsWith("pkg:npm/") ? "npm"
                  : "other",
                c.License,
                c.Vulnerabilities.Count,
                c.SbomSnapshot!.ComponentVersionId,
                c.SbomSnapshot.ComponentVersion!.VersionString,
                c.SbomSnapshot.ComponentVersion.ComponentId,
                c.SbomSnapshot.ComponentVersion.Component!.Name,
                c.SbomSnapshot.ComponentVersion.Component.ProjectId,
                c.SbomSnapshot.ComponentVersion.Component.Project!.Name,
                c.SbomSnapshot.ComponentVersion.Component.Project.ClientId,
                c.SbomSnapshot.ComponentVersion.Component.Project.Client!.Name))
            .ToListAsync(ct);

        return TypedResults.Ok(new SbomComponentsListResponse(
            total, skip, take,
            new EcosystemCounts(nugetCount, npmCount, otherCount),
            totalVulns,
            rows));
    }

    private static async Task<Results<Ok<SbomComponentDetail>, NotFound>> DetailAsync(Guid id, FindingsDbContext db, CancellationToken ct)
    {
        var c = await db.SbomComponents
            .Include(x => x.Vulnerabilities)
            .Include(x => x.SbomSnapshot)!.ThenInclude(s => s!.ComponentVersion)
            .AsNoTracking()
            .FirstOrDefaultAsync(x => x.Id == id, ct);
        if (c is null) return TypedResults.NotFound();

        // Resolve dep edges in/out of this component to PURLs for the panel.
        var snapshotId = c.SbomSnapshotId;
        var outEdges = await (
            from d in db.SbomDependencies.AsNoTracking()
            where d.SbomSnapshotId == snapshotId && d.ParentComponentId == c.Id
            join child in db.SbomComponents.AsNoTracking() on d.ChildComponentId equals child.Id
            select child.Purl).ToListAsync(ct);
        var inEdges = await (
            from d in db.SbomDependencies.AsNoTracking()
            where d.SbomSnapshotId == snapshotId && d.ChildComponentId == c.Id
            join parent in db.SbomComponents.AsNoTracking() on d.ParentComponentId equals parent.Id
            select parent.Purl).ToListAsync(ct);

        return TypedResults.Ok(new SbomComponentDetail(
            c.Id,
            c.Purl,
            c.Name,
            c.Version,
            c.Kind,
            EcosystemFromPurl(c.Purl),
            c.License,
            c.SbomSnapshot!.ComponentVersionId,
            c.SbomSnapshot.ComponentVersion!.VersionString,
            c.Vulnerabilities.Select(v => new VulnerabilityDetail(
                v.Id, v.AdvisoryId, v.Severity.ToString(), v.Title, v.Description,
                v.FixedInVersion, v.ReferenceUrl, v.Source.ToString())).ToList(),
            outEdges,
            inEdges));
    }
}
