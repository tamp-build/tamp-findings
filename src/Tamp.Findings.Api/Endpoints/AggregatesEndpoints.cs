using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Api.Contracts;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Api.Endpoints;

public static class AggregatesEndpoints
{
    public static IEndpointRouteBuilder MapAggregates(this IEndpointRouteBuilder app)
    {
        app.MapGet("/aggregates", GetAsync)
           .WithName("GetAggregates")
           .WithSummary("Rolled-up findings + SBOM counts for the hierarchy ring view. Scope by setting exactly one of clientId/projectId/componentId; no filter returns the org-wide total.");
        return app;
    }

    private static async Task<Ok<AggregatesResponse>> GetAsync(
        FindingsDbContext db,
        CancellationToken ct,
        Guid? clientId = null,
        Guid? projectId = null,
        Guid? componentId = null,
        bool latest = true)
    {
        // Resolve scope label + names (for the ring center) before issuing
        // the heavy aggregate queries.
        var scope = await ResolveScopeAsync(db, clientId, projectId, componentId, ct);

        // --- Findings half ---------------------------------------------------
        // Latest-CV semantic mirrors /findings: by default scope to the
        // current snapshot per (Component, Flavor); the ring shouldn't
        // accumulate across historical builds.
        var fq = db.Findings.AsNoTracking().Where(f => f.Status == FindingStatus.Open);
        if (componentId is { } cmp) fq = fq.Where(f => f.ComponentVersion!.ComponentId == cmp);
        if (projectId is { } prj) fq = fq.Where(f => f.ComponentVersion!.Component!.ProjectId == prj);
        if (clientId is { } cli) fq = fq.Where(f => f.ComponentVersion!.Component!.Project!.ClientId == cli);

        if (latest)
        {
            var latestCvIds = await db.ComponentVersions
                .GroupBy(v => new { v.ComponentId, FlavorKey = v.FlavorId ?? Guid.Empty })
                .Select(g => g.OrderByDescending(v => v.CreatedAt).First().Id)
                .ToListAsync(ct);
            fq = fq.Where(f => latestCvIds.Contains(f.ComponentVersionId));
        }

        var countsBySeverity = await fq
            .GroupBy(f => f.Severity)
            .Select(g => new { g.Key, Count = g.Count() })
            .ToDictionaryAsync(x => x.Key, x => x.Count, ct);

        var counts = new SeverityCounts(
            countsBySeverity.GetValueOrDefault(Severity.Info, 0),
            countsBySeverity.GetValueOrDefault(Severity.Low, 0),
            countsBySeverity.GetValueOrDefault(Severity.Medium, 0),
            countsBySeverity.GetValueOrDefault(Severity.High, 0),
            countsBySeverity.GetValueOrDefault(Severity.Critical, 0));

        var byScanner = await fq
            .GroupBy(f => f.Scanner)
            .Select(g => new { g.Key, Count = g.Count() })
            .ToDictionaryAsync(x => x.Key.ToString(), x => x.Count, ct);

        // Status breakdown — across ALL statuses, not just Open, so the
        // user can see how much is currently suppressed/accepted/fixed.
        // Build a separate query that doesn't filter status.
        var statusQ = db.Findings.AsNoTracking().AsQueryable();
        if (componentId is { } cmp2) statusQ = statusQ.Where(f => f.ComponentVersion!.ComponentId == cmp2);
        if (projectId is { } prj2) statusQ = statusQ.Where(f => f.ComponentVersion!.Component!.ProjectId == prj2);
        if (clientId is { } cli2) statusQ = statusQ.Where(f => f.ComponentVersion!.Component!.Project!.ClientId == cli2);
        if (latest)
        {
            var latestCvIds2 = await db.ComponentVersions
                .GroupBy(v => new { v.ComponentId, FlavorKey = v.FlavorId ?? Guid.Empty })
                .Select(g => g.OrderByDescending(v => v.CreatedAt).First().Id)
                .ToListAsync(ct);
            statusQ = statusQ.Where(f => latestCvIds2.Contains(f.ComponentVersionId));
        }
        var byStatus = await statusQ
            .GroupBy(f => f.Status)
            .Select(g => new { g.Key, Count = g.Count() })
            .ToDictionaryAsync(x => x.Key.ToString(), x => x.Count, ct);

        // Per-scanner detail: every (Scanner, Severity, Status) bucket
        // pulled in one query, pivoted client-side. The donut needs both
        // the open-by-severity split AND the closed/suppressed/accepted
        // totals — keeping it in one round-trip beats per-scanner queries.
        var rawBuckets = await statusQ
            .GroupBy(f => new { f.Scanner, f.Severity, f.Status })
            .Select(g => new { g.Key.Scanner, g.Key.Severity, g.Key.Status, Count = g.Count() })
            .ToListAsync(ct);

        var byScannerDetail = rawBuckets
            .GroupBy(b => b.Scanner)
            .Select(g =>
            {
                int OpenBy(Severity sev) => g
                    .Where(x => x.Status == FindingStatus.Open && x.Severity == sev)
                    .Sum(x => x.Count);
                int StatusTotal(FindingStatus s) => g
                    .Where(x => x.Status == s)
                    .Sum(x => x.Count);
                return new ScannerDetail(
                    Scanner: g.Key.ToString(),
                    Open: new SeverityCounts(
                        Info: OpenBy(Severity.Info),
                        Low: OpenBy(Severity.Low),
                        Medium: OpenBy(Severity.Medium),
                        High: OpenBy(Severity.High),
                        Critical: OpenBy(Severity.Critical)),
                    Closed: StatusTotal(FindingStatus.Fixed),
                    Suppressed: StatusTotal(FindingStatus.Suppressed),
                    Accepted: StatusTotal(FindingStatus.Accepted));
            })
            .OrderBy(d => d.Scanner)
            .ToList();

        // --- SBOM half -------------------------------------------------------
        var sq = db.SbomComponents.AsNoTracking();
        if (componentId is { } cmp3) sq = sq.Where(c => c.SbomSnapshot!.ComponentVersion!.ComponentId == cmp3);
        if (projectId is { } prj3) sq = sq.Where(c => c.SbomSnapshot!.ComponentVersion!.Component!.ProjectId == prj3);
        if (clientId is { } cli3) sq = sq.Where(c => c.SbomSnapshot!.ComponentVersion!.Component!.Project!.ClientId == cli3);

        if (latest)
        {
            var latestSnapshotIds = await db.SbomSnapshots
                .GroupBy(s => new { s.ComponentVersion!.ComponentId, FlavorKey = s.ComponentVersion.FlavorId ?? Guid.Empty })
                .Select(g => g.OrderByDescending(s => s.IngestedAt).First().Id)
                .ToListAsync(ct);
            sq = sq.Where(c => latestSnapshotIds.Contains(c.SbomSnapshotId));
        }

        var compsCount = await sq.CountAsync(ct);
        var vulnsCount = await sq.SelectMany(c => c.Vulnerabilities).CountAsync(ct);
        var byEcosystemList = await sq
            .GroupBy(c => c.Purl.StartsWith("pkg:nuget/") ? "nuget"
                          : c.Purl.StartsWith("pkg:npm/") ? "npm"
                          : "other")
            .Select(g => new { Eco = g.Key, Count = g.Count() })
            .ToListAsync(ct);
        var byEcosystem = byEcosystemList.ToDictionary(x => x.Eco, x => x.Count);

        // SBOM health rollup — vulnerable wins over outdated wins over current.
        var vulnerable = await sq.Where(c => c.Vulnerabilities.Any()).CountAsync(ct);
        var outdated = await sq
            .Where(c => !c.Vulnerabilities.Any()
                     && c.LatestVersion != null
                     && c.LatestVersion != c.Version)
            .CountAsync(ct);
        var current = compsCount - vulnerable - outdated;

        // Secrets ring: TruffleHog Critical = verified, High = unverified.
        // Scoped same as the other finding metrics (open + latest CV).
        var secretsBase = db.Findings
            .AsNoTracking()
            .Where(f => f.Scanner == ScannerKind.TruffleHog && f.Status == FindingStatus.Open);
        if (componentId is { } cmp4) secretsBase = secretsBase.Where(f => f.ComponentVersion!.ComponentId == cmp4);
        if (projectId is { } prj4) secretsBase = secretsBase.Where(f => f.ComponentVersion!.Component!.ProjectId == prj4);
        if (clientId is { } cli4) secretsBase = secretsBase.Where(f => f.ComponentVersion!.Component!.Project!.ClientId == cli4);
        if (latest)
        {
            var latestCvIds3 = await db.ComponentVersions
                .GroupBy(v => new { v.ComponentId, FlavorKey = v.FlavorId ?? Guid.Empty })
                .Select(g => g.OrderByDescending(v => v.CreatedAt).First().Id)
                .ToListAsync(ct);
            secretsBase = secretsBase.Where(f => latestCvIds3.Contains(f.ComponentVersionId));
        }
        var verifiedSecrets = await secretsBase.CountAsync(f => f.Severity == Severity.Critical, ct);
        var unverifiedSecrets = await secretsBase.CountAsync(f => f.Severity == Severity.High, ct);

        return TypedResults.Ok(new AggregatesResponse(
            scope,
            new FindingAggregate(counts, byScanner, byStatus, byScannerDetail),
            new SbomAggregate(
                compsCount, vulnsCount, byEcosystem,
                new SbomHealthCounts(current, outdated, vulnerable)),
            new SecretsAggregate(new SecretsHealthCounts(verifiedSecrets, unverifiedSecrets))));
    }

    private static async Task<AggregateScope> ResolveScopeAsync(
        FindingsDbContext db,
        Guid? clientId,
        Guid? projectId,
        Guid? componentId,
        CancellationToken ct)
    {
        if (componentId is { } cmpId)
        {
            var row = await (
                from c in db.Components.AsNoTracking()
                where c.Id == cmpId
                join p in db.Projects.AsNoTracking() on c.ProjectId equals p.Id
                join cli in db.Clients.AsNoTracking() on p.ClientId equals cli.Id
                select new { cli.Name, ProjectName = p.Name, ComponentName = c.Name }
            ).FirstOrDefaultAsync(ct);
            if (row is not null)
                return new AggregateScope(row.Name, row.ProjectName, row.ComponentName,
                    $"{row.Name} / {row.ProjectName} / {row.ComponentName}", "Component");
        }
        if (projectId is { } prjId)
        {
            var row = await (
                from p in db.Projects.AsNoTracking()
                where p.Id == prjId
                join cli in db.Clients.AsNoTracking() on p.ClientId equals cli.Id
                select new { cli.Name, ProjectName = p.Name }
            ).FirstOrDefaultAsync(ct);
            if (row is not null)
                return new AggregateScope(row.Name, row.ProjectName, null,
                    $"{row.Name} / {row.ProjectName}", "Project");
        }
        if (clientId is { } cliId)
        {
            var row = await db.Clients.AsNoTracking().FirstOrDefaultAsync(c => c.Id == cliId, ct);
            if (row is not null)
                return new AggregateScope(row.Name, null, null, row.Name, "Client");
        }
        return new AggregateScope(null, null, null, "All", "All");
    }
}
