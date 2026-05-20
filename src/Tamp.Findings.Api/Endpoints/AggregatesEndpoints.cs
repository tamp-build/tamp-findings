using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Api.Contracts;
using Tamp.Findings.Api.Services;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
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

        // Top-N rules across the latest CVs in scope. Severity is the worst
        // observed for the rule (rules occasionally span severities in
        // theory, never in practice for our scanners). Used by the Overview
        // "Top rules" table — TFND-18.
        var ruleRows = await statusQ
            .Where(f => f.Status == FindingStatus.Open)
            .GroupBy(f => f.RuleId)
            .Select(g => new
            {
                RuleId = g.Key,
                Count = g.Count(),
                MaxSeverity = g.Max(f => f.Severity),
                AnyScanner = g.Min(f => f.Scanner),
            })
            .OrderByDescending(r => r.Count)
            .Take(10)
            .ToListAsync(ct);
        var byRule = ruleRows
            .Select(r => new FindingRuleSummaryDto(
                RuleId: r.RuleId,
                Count: r.Count,
                Severity: r.MaxSeverity,
                Scanner: r.AnyScanner))
            .ToList();

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

        // License posture: pull the license string for every component in
        // scope, classify into a permissiveness tier, build the per-string
        // count map for the "% of licenses" table.
        var licenseRows = await sq
            .Select(c => c.License)
            .ToListAsync(ct);
        var byLicense = new Dictionary<string, int>(StringComparer.Ordinal);
        var perm = 0; var weak = 0; var strong = 0; var denied = 0; var unknown = 0;
        foreach (var raw in licenseRows)
        {
            var key = string.IsNullOrWhiteSpace(raw) ? "(unknown)" : raw.Trim();
            byLicense[key] = byLicense.GetValueOrDefault(key) + 1;
            switch (LicensePolicy.Classify(raw))
            {
                case LicensePolicy.Tier.Permissive:     perm++; break;
                case LicensePolicy.Tier.WeakCopyleft:   weak++; break;
                case LicensePolicy.Tier.StrongCopyleft: strong++; break;
                case LicensePolicy.Tier.Denied:         denied++; break;
                default:                                unknown++; break;
            }
        }

        // IaC bullseye: Trivy findings bucketed by severity. Scanned status
        // now comes from ScanRunReceipts (TFND-15) — a Trivy receipt in scope
        // means the scanner ran. Falls back to the old heuristic ("any Trivy
        // finding in scope") so older ingests without receipts still work.
        var iacBase = db.Findings
            .AsNoTracking()
            .Where(f => f.Scanner == ScannerKind.Trivy && f.Status == FindingStatus.Open);
        if (componentId is { } cmp5) iacBase = iacBase.Where(f => f.ComponentVersion!.ComponentId == cmp5);
        if (projectId is { } prj5) iacBase = iacBase.Where(f => f.ComponentVersion!.Component!.ProjectId == prj5);
        if (clientId is { } cli5) iacBase = iacBase.Where(f => f.ComponentVersion!.Component!.Project!.ClientId == cli5);
        if (latest)
        {
            var latestCvIds4 = await db.ComponentVersions
                .GroupBy(v => new { v.ComponentId, FlavorKey = v.FlavorId ?? Guid.Empty })
                .Select(g => g.OrderByDescending(v => v.CreatedAt).First().Id)
                .ToListAsync(ct);
            iacBase = iacBase.Where(f => latestCvIds4.Contains(f.ComponentVersionId));
        }
        var iacBySev = await iacBase
            .GroupBy(f => f.Severity)
            .Select(g => new { g.Key, Count = g.Count() })
            .ToDictionaryAsync(x => x.Key, x => x.Count, ct);
        var iacCounts = new SeverityCounts(
            iacBySev.GetValueOrDefault(Severity.Info, 0),
            iacBySev.GetValueOrDefault(Severity.Low, 0),
            iacBySev.GetValueOrDefault(Severity.Medium, 0),
            iacBySev.GetValueOrDefault(Severity.High, 0),
            iacBySev.GetValueOrDefault(Severity.Critical, 0));
        // Scanned flag: include closed/suppressed/accepted in the "did we
        // ever see Trivy data" check so a once-found-now-fixed finding
        // still counts as evidence the scanner ran.
        var trivySeenAnywhere = await db.Findings
            .AsNoTracking()
            .AnyAsync(f => f.Scanner == ScannerKind.Trivy, ct);

        // Coverage rollup: latest CoverageReport per CV in scope, sum the
        // covered/total counts, recompute the percentage. If no report
        // exists for any CV in scope, Measured=false → SPA renders grey.
        var coverageQ = db.CoverageReports.AsNoTracking();
        if (componentId is { } cmp6) coverageQ = coverageQ.Where(r => r.ComponentVersion!.ComponentId == cmp6);
        if (projectId is { } prj6) coverageQ = coverageQ.Where(r => r.ComponentVersion!.Component!.ProjectId == prj6);
        if (clientId is { } cli6) coverageQ = coverageQ.Where(r => r.ComponentVersion!.Component!.Project!.ClientId == cli6);
        if (latest)
        {
            var latestCvIds5 = await db.ComponentVersions
                .GroupBy(v => new { v.ComponentId, FlavorKey = v.FlavorId ?? Guid.Empty })
                .Select(g => g.OrderByDescending(v => v.CreatedAt).First().Id)
                .ToListAsync(ct);
            coverageQ = coverageQ.Where(r => latestCvIds5.Contains(r.ComponentVersionId));
        }
        var coverageReports = await coverageQ.Include(r => r.Modules).ToListAsync(ct);
        CoverageAggregate coverage;
        if (coverageReports.Count == 0)
        {
            coverage = new CoverageAggregate(Measured: false, null, null, 0, 0, []);
        }
        else
        {
            var totSeq = coverageReports.Sum(r => r.TotalSequences);
            var covSeq = coverageReports.Sum(r => r.CoveredSequences);
            var totBr = coverageReports.Sum(r => r.TotalBranches);
            var covBr = coverageReports.Sum(r => r.CoveredBranches);
            // Module-level: aggregate by module name across reports (in scope
            // multiple reports may share a module — e.g., when both test
            // projects cover the same domain assembly).
            var moduleAgg = coverageReports
                .SelectMany(r => r.Modules)
                .GroupBy(m => m.Name, StringComparer.OrdinalIgnoreCase)
                .Select(g => new CoverageModuleSummary(
                    g.Key,
                    SequenceCoverage: g.Sum(m => m.TotalSequences) == 0
                        ? 0
                        : 100.0 * g.Sum(m => m.CoveredSequences) / g.Sum(m => m.TotalSequences),
                    CoveredSequences: g.Sum(m => m.CoveredSequences),
                    TotalSequences: g.Sum(m => m.TotalSequences)))
                .OrderBy(m => m.SequenceCoverage)   // worst first → draws eye to the gaps
                .ToList();
            coverage = new CoverageAggregate(
                Measured: true,
                SequenceCoverage: totSeq == 0 ? 0 : 100.0 * covSeq / totSeq,
                BranchCoverage: totBr == 0 ? 0 : 100.0 * covBr / totBr,
                CoveredSequences: covSeq,
                TotalSequences: totSeq,
                Modules: moduleAgg);
        }

        // Scan-run receipts in scope (TFND-15). One receipt per (CV, Scanner)
        // for every latest CV picked above. Surfaced to the SPA so a scanner
        // that ran clean reads as "scanned ✓" instead of grey "never ran".
        var scanRunsQ = db.ScanRunReceipts.AsNoTracking();
        if (componentId is { } cmp7) scanRunsQ = scanRunsQ.Where(r => r.ComponentVersion!.ComponentId == cmp7);
        if (projectId is { } prj7) scanRunsQ = scanRunsQ.Where(r => r.ComponentVersion!.Component!.ProjectId == prj7);
        if (clientId is { } cli7) scanRunsQ = scanRunsQ.Where(r => r.ComponentVersion!.Component!.Project!.ClientId == cli7);
        if (latest)
        {
            var latestCvIds6 = await db.ComponentVersions
                .GroupBy(v => new { v.ComponentId, FlavorKey = v.FlavorId ?? Guid.Empty })
                .Select(g => g.OrderByDescending(v => v.CreatedAt).First().Id)
                .ToListAsync(ct);
            scanRunsQ = scanRunsQ.Where(r => latestCvIds6.Contains(r.ComponentVersionId));
        }
        var scanRunRows = await scanRunsQ
            .Select(r => new
            {
                r.Scanner, r.Status, r.CompletedAt, r.FindingsCount, r.ToolName, r.ToolVersion,
            })
            .ToListAsync(ct);
        // Group + pick-latest in memory — EF Core can't translate
        // "GroupBy + OrderByDescending + First" into SQL for this query.
        var scanRuns = scanRunRows
            .GroupBy(r => r.Scanner)
            .Select(g =>
            {
                var latest = g.OrderByDescending(x => x.CompletedAt).First();
                return new ScanRunSummaryDto(
                    latest.Scanner, latest.Status, latest.CompletedAt,
                    latest.FindingsCount, latest.ToolName, latest.ToolVersion);
            })
            .OrderBy(r => r.Scanner.ToString())
            .ToList();

        // IaC ring is scanned-clean when a Trivy receipt exists OR (older
        // heuristic) any Trivy finding has ever been ingested in scope.
        var iacScanned = trivySeenAnywhere
            || scanRuns.Any(r => r.Scanner == ScannerKind.Trivy && r.Status == ScanRunStatus.Succeeded);

        return TypedResults.Ok(new AggregatesResponse(
            scope,
            new FindingAggregate(counts, byScanner, byStatus, byScannerDetail, byRule),
            new SbomAggregate(
                compsCount, vulnsCount, byEcosystem,
                new SbomHealthCounts(current, outdated, vulnerable)),
            new SecretsAggregate(new SecretsHealthCounts(verifiedSecrets, unverifiedSecrets)),
            new LicensesAggregate(
                new LicenseTierCounts(perm, weak, strong, denied, unknown),
                byLicense),
            new IacAggregate(iacCounts, Scanned: iacScanned),
            coverage,
            scanRuns));
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
