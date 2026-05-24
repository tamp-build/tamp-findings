using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Api.Contracts;
using Tamp.Findings.Api.Services;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Risk;
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
            var latestCvIds = await CanonicalOnly(db.ComponentVersions)
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
            var latestCvIds2 = await CanonicalOnly(db.ComponentVersions)
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
        // TFND-22: "stale" = outdated AND latest release is more than 180 days
        // ago. Sub-bucket of outdated so the user can see how much of the
        // outdated pile has actually been sitting for a while vs. dropped
        // behind in the last few weeks.
        var staleCutoff = DateTimeOffset.UtcNow.AddDays(-180);
        var stale = await sq
            .Where(c => !c.Vulnerabilities.Any()
                     && c.LatestVersion != null
                     && c.LatestVersion != c.Version
                     && c.LatestReleasedAt != null
                     && c.LatestReleasedAt < staleCutoff)
            .CountAsync(ct);

        // Secrets ring: TruffleHog Critical = verified, High = unverified.
        // TFND-17 expands this to also count Trivy findings tagged
        // SubCategory="secret" alongside TruffleHog so the ring reflects
        // every secret regardless of which tool spotted it.
        var secretsBase = db.Findings
            .AsNoTracking()
            .Where(f => f.Status == FindingStatus.Open
                     && (f.Scanner == ScannerKind.TruffleHog
                         || (f.Scanner == ScannerKind.Trivy && f.SubCategory == "secret")));
        if (componentId is { } cmp4) secretsBase = secretsBase.Where(f => f.ComponentVersion!.ComponentId == cmp4);
        if (projectId is { } prj4) secretsBase = secretsBase.Where(f => f.ComponentVersion!.Component!.ProjectId == prj4);
        if (clientId is { } cli4) secretsBase = secretsBase.Where(f => f.ComponentVersion!.Component!.Project!.ClientId == cli4);
        if (latest)
        {
            var latestCvIds3 = await CanonicalOnly(db.ComponentVersions)
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

        // IaC bullseye: Trivy findings bucketed by severity. TFND-17 narrows
        // this to only Trivy(misconfiguration) — Trivy(secret) feeds the
        // Secrets ring, Trivy(vulnerability) flows through the SBOM ring
        // via the OSV-style upsert. Findings ingested before SubCategory
        // existed have null and still count here (back-compat).
        var iacBase = db.Findings
            .AsNoTracking()
            .Where(f => f.Scanner == ScannerKind.Trivy && f.Status == FindingStatus.Open
                     && (f.SubCategory == null || f.SubCategory == "misconfiguration"));
        if (componentId is { } cmp5) iacBase = iacBase.Where(f => f.ComponentVersion!.ComponentId == cmp5);
        if (projectId is { } prj5) iacBase = iacBase.Where(f => f.ComponentVersion!.Component!.ProjectId == prj5);
        if (clientId is { } cli5) iacBase = iacBase.Where(f => f.ComponentVersion!.Component!.Project!.ClientId == cli5);
        if (latest)
        {
            var latestCvIds4 = await CanonicalOnly(db.ComponentVersions)
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
            var latestCvIds5 = await CanonicalOnly(db.ComponentVersions)
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
            var latestCvIds6 = await CanonicalOnly(db.ComponentVersions)
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

        // ---- Risk score --------------------------------------------------
        // CVE severities for the scorer. Walks SbomVulnerabilities scoped
        // through SbomComponent → SbomSnapshot → ComponentVersion. Only the
        // latest snapshot per CV is counted (snapshots are replace-on-ingest,
        // so there's at most one per CV anyway).
        var vulnsQ = db.Vulnerabilities.AsNoTracking()
            .Where(v => v.SbomComponent!.SbomSnapshot!.ComponentVersionId != Guid.Empty);
        if (componentId is { } cmpV) vulnsQ = vulnsQ.Where(v => v.SbomComponent!.SbomSnapshot!.ComponentVersion!.ComponentId == cmpV);
        if (projectId  is { } prjV) vulnsQ = vulnsQ.Where(v => v.SbomComponent!.SbomSnapshot!.ComponentVersion!.Component!.ProjectId == prjV);
        if (clientId   is { } cliV) vulnsQ = vulnsQ.Where(v => v.SbomComponent!.SbomSnapshot!.ComponentVersion!.Component!.Project!.ClientId == cliV);
        var cveSev = await vulnsQ
            .GroupBy(v => v.Severity)
            .Select(g => new { g.Key, Count = g.Count() })
            .ToDictionaryAsync(x => x.Key, x => x.Count, ct);

        // Test results — latest TestRunReport per CV in scope, summed.
        var testQ = db.TestRunReports.AsNoTracking();
        if (componentId is { } cmpT) testQ = testQ.Where(r => r.ComponentVersion!.ComponentId == cmpT);
        if (projectId  is { } prjT) testQ = testQ.Where(r => r.ComponentVersion!.Component!.ProjectId == prjT);
        if (clientId   is { } cliT) testQ = testQ.Where(r => r.ComponentVersion!.Component!.Project!.ClientId == cliT);
        var testReports = await testQ.ToListAsync(ct);
        var testsMeasured = testReports.Count > 0;
        var testsTotal = testReports.Sum(r => r.TotalCount);
        var testsFailed = testReports.Sum(r => r.FailedCount);

        // SAST severity counts: pull from byScannerDetail (already
        // populated above with the canonical SAST set). Scanner is a
        // string on the DTO — parse back to the enum to gate.
        var sastDetail = byScannerDetail
            .Where(d => Enum.TryParse<ScannerKind>(d.Scanner, out var k) && RingChartSastSet.Contains(k))
            .ToList();
        var sastCrit = sastDetail.Sum(d => d.Open.Critical);
        var sastHigh = sastDetail.Sum(d => d.Open.High);
        var sastMed  = sastDetail.Sum(d => d.Open.Medium);
        var sastLow  = sastDetail.Sum(d => d.Open.Low);

        // Which scanner classes ran? Borrow the existing scan-run roll-up.
        bool RanSucc(ScannerKind k) => scanRuns.Any(r => r.Scanner == k && r.Status == ScanRunStatus.Succeeded);
        var ranSast = (new[] { ScannerKind.Roslyn, ScannerKind.ReSharper, ScannerKind.OpenGrep, ScannerKind.CodeQL, ScannerKind.ESLint }).Any(RanSucc);
        var ranSecrets = RanSucc(ScannerKind.TruffleHog);
        var ranIac = RanSucc(ScannerKind.Trivy);
        var ranSbom = compsCount > 0 || RanSucc(ScannerKind.Syft) || RanSucc(ScannerKind.OsvScanner);
        var ranCoverage = coverage.Measured;

        var inputs = new RiskInputs(
            CveCritical: cveSev.GetValueOrDefault(Severity.Critical, 0),
            CveHigh:     cveSev.GetValueOrDefault(Severity.High, 0),
            CveMedium:   cveSev.GetValueOrDefault(Severity.Medium, 0),
            CveLow:      cveSev.GetValueOrDefault(Severity.Low, 0),
            SecretsVerified: verifiedSecrets,
            SecretsUnverified: unverifiedSecrets,
            SastCritical: sastCrit, SastHigh: sastHigh, SastMedium: sastMed, SastLow: sastLow,
            IacCritical: iacCounts.Critical, IacHigh: iacCounts.High,
            CoverageMeasured: coverage.Measured,
            SequenceCoveragePercent: coverage.SequenceCoverage ?? 0,
            SbomComponents: compsCount, SbomOutdated: outdated, SbomStale: stale,
            TestsMeasured: testsMeasured, TestsTotal: testsTotal, TestsFailed: testsFailed,
            LicenseDenied: denied, LicenseStrongCopyleft: strong, LicenseUnknown: unknown,
            RanSast: ranSast, RanSecrets: ranSecrets, RanIac: ranIac,
            RanSbom: ranSbom, RanCoverage: ranCoverage);

        // Render risk = null when the scope has zero ingest evidence — a
        // brand-new client with no scanners ran shouldn't show a number.
        RiskScoreDto? risk = null;
        var hasAnyEvidence = compsCount > 0 || counts.Total > 0 || scanRuns.Count > 0
            || coverage.Measured || testsMeasured;
        if (hasAnyEvidence)
        {
            var policy = await ResolveEffectivePolicyAsync(db, clientId, projectId, componentId, ct);
            if (policy is not null)
            {
                var result = RiskScorer.Compute(policy.Config, inputs);
                risk = new RiskScoreDto(
                    Score: Math.Round(result.Score, 1),
                    Band: result.Band,
                    PolicyId: policy.Id,
                    PolicyName: policy.Name,
                    SchemaVersion: result.SchemaVersion,
                    Breakdown: result.Breakdown.Select(b => new RiskBreakdownDto(
                        b.Key, b.Enabled, b.Max,
                        Math.Round(b.SubScore, 4),
                        Math.Round(b.Contribution, 2))).ToList());
            }
        }

        return TypedResults.Ok(new AggregatesResponse(
            scope,
            new FindingAggregate(counts, byScanner, byStatus, byScannerDetail, byRule),
            new SbomAggregate(
                compsCount, vulnsCount, byEcosystem,
                new SbomHealthCounts(current, outdated, vulnerable, stale)),
            new SecretsAggregate(new SecretsHealthCounts(verifiedSecrets, unverifiedSecrets)),
            new LicensesAggregate(
                new LicenseTierCounts(perm, weak, strong, denied, unknown),
                byLicense),
            new IacAggregate(iacCounts, Scanned: iacScanned),
            coverage,
            scanRuns,
            risk));
    }

    // SAST scanner set used by the Code Quality ring. Kept here so the
    // risk scorer's SAST inputs match what the donut shows the user.
    private static readonly HashSet<ScannerKind> RingChartSastSet =
    [
        ScannerKind.Roslyn, ScannerKind.ReSharper, ScannerKind.OpenGrep, ScannerKind.CodeQL,
        ScannerKind.ESLint,
    ];

    // Canonical = the project's actual state, NOT a PR/branch acceptance
    // gate. Risk score always uses canonical-only (acceptance-gate posture).
    // Heuristic for v1: no PR ref AND branch is null/main/master. A future
    // Project.DefaultBranch column would supersede this.
    private static IQueryable<ComponentVersion> CanonicalOnly(IQueryable<ComponentVersion> q) =>
        q.Where(v => v.PullRequestRef == null
                  && (v.BranchName == null || v.BranchName == "main" || v.BranchName == "master"));

    // Project > Client > Default fallback. Returns null only if NO
    // RiskPolicy rows exist at all (the seeder should have prevented that).
    private static async Task<RiskPolicy?> ResolveEffectivePolicyAsync(
        FindingsDbContext db, Guid? clientId, Guid? projectId, Guid? componentId, CancellationToken ct)
    {
        Guid? projectPolicyId = null;
        Guid? clientPolicyId = null;

        if (componentId is { } cmp)
        {
            var pair = await db.Components.AsNoTracking()
                .Where(c => c.Id == cmp)
                .Select(c => new
                {
                    ProjectPolicy = c.Project!.RiskPolicyId,
                    ClientPolicy = c.Project.Client!.RiskPolicyId,
                })
                .FirstOrDefaultAsync(ct);
            projectPolicyId = pair?.ProjectPolicy;
            clientPolicyId = pair?.ClientPolicy;
        }
        else if (projectId is { } prj)
        {
            var pair = await db.Projects.AsNoTracking()
                .Where(p => p.Id == prj)
                .Select(p => new { p.RiskPolicyId, ClientPolicy = p.Client!.RiskPolicyId })
                .FirstOrDefaultAsync(ct);
            projectPolicyId = pair?.RiskPolicyId;
            clientPolicyId = pair?.ClientPolicy;
        }
        else if (clientId is { } cli)
        {
            clientPolicyId = await db.Clients.AsNoTracking()
                .Where(c => c.Id == cli)
                .Select(c => c.RiskPolicyId)
                .FirstOrDefaultAsync(ct);
        }

        var effectiveId = projectPolicyId ?? clientPolicyId;
        if (effectiveId is { } id)
        {
            var byId = await db.RiskPolicies.AsNoTracking().FirstOrDefaultAsync(p => p.Id == id, ct);
            if (byId is not null) return byId;
        }
        return await db.RiskPolicies.AsNoTracking().FirstOrDefaultAsync(p => p.IsDefault, ct);
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
