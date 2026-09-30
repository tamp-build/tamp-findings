using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Application.Risk;

/// <summary>
/// The findings that make up one scored category, for the category detail page
/// (v3 §3). This resolves the build's canonical component-version set the same
/// way the hub does, then filters the Findings table by the category's own
/// classification — the SAME scanner/severity/sub-category rules RiskInputsBuilder
/// scores against, so the list and the number cannot disagree.
///
/// Only the FINDINGS-table categories are answered here (sastSevere, sastLow,
/// secrets, iacSevere). cve (SBOM vulnerabilities), coverage, tests, license,
/// sbomStaleness and missingScanners have their own data sources and their own
/// queries; this returns an empty list for them.
/// </summary>
public sealed class CategoryFindingsQuery(FindingsDbContext db)
{
    // The build's CV set: the requested commit, or the latest canonical one.
    private async Task<Guid[]> ResolveCvIdsAsync(Guid projectId, string? commitSha, CancellationToken ct)
    {
        var sha = commitSha;
        if (string.IsNullOrWhiteSpace(sha))
        {
            sha = await db.ComponentVersions.AsNoTracking()
                .Where(cv => cv.ProjectId == projectId)
                .OrderByDescending(cv => cv.CreatedAt)
                .Select(cv => cv.CommitSha)
                .FirstOrDefaultAsync(ct);
        }
        if (sha is null) return [];

        return await db.ComponentVersions.AsNoTracking()
            .Where(cv => cv.CommitSha == sha
                && cv.ProjectId == projectId)
            .Select(cv => cv.Id)
            .ToArrayAsync(ct);
    }

    public async Task<IReadOnlyList<CategoryFinding>> LoadAsync(
        Guid projectId, string? commitSha, string categoryKey, CancellationToken ct = default)
    {
        var cvIds = await ResolveCvIdsAsync(projectId, commitSha, ct);
        if (cvIds.Length == 0) return [];

        var q = db.Findings.AsNoTracking().Where(f => cvIds.Contains(f.ComponentVersionId));
        q = Filter(categoryKey, q);
        if (q is null) return [];

        return await q
            .OrderByDescending(f => f.Severity)
            .ThenBy(f => f.FilePath)
            .ThenBy(f => f.Line)
            .Select(f => new CategoryFinding(
                f.Id, f.Scanner, f.RuleId, f.Severity, f.Title, f.Description,
                f.FilePath, f.Line, f.Snippet, f.SubCategory, f.Status, f.FirstSeen))
            .ToListAsync(ct);
    }

    /// <summary>Known-CVE rows for the `cve` category, from the SBOM vulnerabilities.</summary>
    public async Task<IReadOnlyList<CveRow>> CvesAsync(
        Guid projectId, string? commitSha, CancellationToken ct = default)
    {
        var cvIds = await ResolveCvIdsAsync(projectId, commitSha, ct);
        if (cvIds.Length == 0) return [];

        return await db.Vulnerabilities.AsNoTracking()
            .Where(v => cvIds.Contains(v.SbomComponent!.SbomSnapshot!.ComponentVersionId))
            .OrderByDescending(v => v.Severity).ThenByDescending(v => v.CvssScore ?? 0)
            .Select(v => new CveRow(
                v.AdvisoryId, v.Severity, v.SbomComponent!.Name, v.SbomComponent!.Version,
                v.CvssScore, v.FixedInVersion, v.ReferenceUrl))
            .ToListAsync(ct);
    }

    /// <summary>Aggregated coverage for the `coverage` category, or null when never measured.</summary>
    public async Task<CoverageSummary?> CoverageAsync(
        Guid projectId, string? commitSha, CancellationToken ct = default)
    {
        var cvIds = await ResolveCvIdsAsync(projectId, commitSha, ct);
        if (cvIds.Length == 0) return null;

        var reports = await db.CoverageReports.AsNoTracking()
            .Where(r => cvIds.Contains(r.ComponentVersionId))
            .Select(r => new { r.CoveredSequences, r.TotalSequences, r.CoveredBranches, r.TotalBranches })
            .ToListAsync(ct);
        if (reports.Count == 0) return null;

        var cs = reports.Sum(r => r.CoveredSequences); var ts = reports.Sum(r => r.TotalSequences);
        var cb = reports.Sum(r => r.CoveredBranches); var tb = reports.Sum(r => r.TotalBranches);
        return new CoverageSummary(
            ts == 0 ? 0 : 100.0 * cs / ts, cs, ts,
            tb == 0 ? 0 : 100.0 * cb / tb, cb, tb);
    }

    /// <summary>Test outcomes for the `tests` category. Suite-level — per-test flaky/skipped
    /// detail is not ingested yet (a known model gap), so this reports the suites that failed
    /// or skipped, plus the run totals.</summary>
    public async Task<TestsSummary?> TestsAsync(Guid projectId, string? commitSha, CancellationToken ct = default)
    {
        var cvIds = await ResolveCvIdsAsync(projectId, commitSha, ct);
        if (cvIds.Length == 0) return null;

        var reports = await db.TestRunReports.AsNoTracking()
            .Where(r => cvIds.Contains(r.ComponentVersionId))
            .Select(r => new { r.Id, r.TotalCount, r.PassedCount, r.FailedCount, r.SkippedCount })
            .ToListAsync(ct);
        if (reports.Count == 0) return null;

        var reportIds = reports.Select(r => r.Id).ToArray();
        var suites = await db.TestSuiteResults.AsNoTracking()
            .Where(s => reportIds.Contains(s.TestRunReportId) && (s.FailedCount > 0 || s.SkippedCount > 0))
            .OrderByDescending(s => s.FailedCount).ThenByDescending(s => s.SkippedCount)
            .Select(s => new TestSuiteRow(s.AssemblyName + " · " + s.ClassName, s.FailedCount, s.SkippedCount))
            .Take(200).ToListAsync(ct);

        return new TestsSummary(
            reports.Sum(r => r.TotalCount), reports.Sum(r => r.PassedCount),
            reports.Sum(r => r.FailedCount), reports.Sum(r => r.SkippedCount), suites);
    }

    /// <summary>Licence mix for the `license` category.</summary>
    public async Task<IReadOnlyList<LicenseGroup>> LicensesAsync(Guid projectId, string? commitSha, CancellationToken ct = default)
    {
        var snapIds = await SnapshotIdsAsync(projectId, commitSha, ct);
        if (snapIds.Length == 0) return [];

        var groups = await db.SbomComponents.AsNoTracking()
            .Where(c => snapIds.Contains(c.SbomSnapshotId))
            .GroupBy(c => c.License)
            .Select(g => new { g.Key, Count = g.Count() })
            .OrderByDescending(g => g.Count)
            .ToListAsync(ct);

        return groups.Select(g => new LicenseGroup(g.Key ?? "unknown", g.Count)).ToArray();
    }

    /// <summary>The outdated SBOM components behind the `sbomStaleness` score.
    ///
    /// Mirrors RiskInputsBuilder EXACTLY so the list and the number cannot
    /// disagree: skip vulnerable rows (they score under cve, not here), keep the
    /// rows with a newer version available (<c>outdated</c>), and mark the ones
    /// whose newer release itself shipped over 180 days ago (<c>stale</c> — you
    /// have had the time to adopt it and have not).</summary>
    public async Task<IReadOnlyList<StaleComponent>> SbomStalenessAsync(Guid projectId, string? commitSha, CancellationToken ct = default)
    {
        var snapIds = await SnapshotIdsAsync(projectId, commitSha, ct);
        if (snapIds.Length == 0) return [];

        var cutoff = DateTimeOffset.UtcNow.AddDays(-180);
        var rows = await db.SbomComponents.AsNoTracking()
            .Where(c => snapIds.Contains(c.SbomSnapshotId)
                && c.Vulnerabilities.Count == 0
                && c.LatestVersion != null && c.LatestVersion != "" && c.LatestVersion != c.Version)
            .Select(c => new { c.Name, c.Version, c.LatestVersion, c.LatestReleasedAt })
            .ToListAsync(ct);

        var now = DateTimeOffset.UtcNow;
        return rows
            .Select(c => new StaleComponent(
                c.Name, c.Version, c.LatestVersion,
                c.LatestReleasedAt is { } at ? (int)(now - at).TotalDays : null,
                c.LatestReleasedAt is { } s && s < cutoff))
            .OrderByDescending(c => c.Stale)
            .ThenByDescending(c => c.DaysBehind ?? -1)
            .ThenBy(c => c.Name)
            .Take(100).ToArray();
    }

    /// <summary>Scan-run receipts for the `missingScanners` category — which scanners ran.</summary>
    public async Task<IReadOnlyList<ReceiptRow>> ReceiptsAsync(Guid projectId, string? commitSha, CancellationToken ct = default)
    {
        var cvIds = await ResolveCvIdsAsync(projectId, commitSha, ct);
        if (cvIds.Length == 0) return [];

        return await db.ScanRunReceipts.AsNoTracking()
            .Where(r => cvIds.Contains(r.ComponentVersionId))
            .OrderBy(r => r.Scanner)
            .Select(r => new ReceiptRow(r.Scanner, r.Status.ToString(), r.FindingsCount, r.CompletedAt, r.ToolName, r.ToolVersion, r.Notes))
            .ToListAsync(ct);
    }

    private async Task<Guid[]> SnapshotIdsAsync(Guid projectId, string? commitSha, CancellationToken ct)
    {
        var cvIds = await ResolveCvIdsAsync(projectId, commitSha, ct);
        if (cvIds.Length == 0) return [];
        return await db.SbomSnapshots.AsNoTracking()
            .Where(s => cvIds.Contains(s.ComponentVersionId))
            .Select(s => s.Id).ToArrayAsync(ct);
    }

    // Whether a category key is answered by this query (a findings table).
    public static bool IsFindingsCategory(string key) => key is
        "sastSevere" or "sastLow" or "secrets" or "iacSevere";

    private static readonly ScannerKind[] Sast = ScannerKinds.Sast.ToArray();

    private static IQueryable<Finding>? Filter(string key, IQueryable<Finding> q) => key switch
    {
        "sastSevere" => q.Where(f => Sast.Contains(f.Scanner)
            && (f.Severity == Severity.Critical || f.Severity == Severity.High)),
        "sastLow" => q.Where(f => Sast.Contains(f.Scanner)
            && (f.Severity == Severity.Medium || f.Severity == Severity.Low)),
        // Secrets: TruffleHog, plus Trivy rows tagged secret.
        "secrets" => q.Where(f => f.Scanner == ScannerKind.TruffleHog
            || (f.Scanner == ScannerKind.Trivy && f.SubCategory == "secret")),
        // IaC: Trivy misconfiguration (or untagged Trivy), severe only.
        "iacSevere" => q.Where(f => f.Scanner == ScannerKind.Trivy
            && (f.SubCategory == null || f.SubCategory == "misconfiguration")
            && (f.Severity == Severity.Critical || f.Severity == Severity.High)),
        _ => null,
    };
}

public sealed record CategoryFinding(
    Guid Id,
    ScannerKind Scanner,
    string RuleId,
    Severity Severity,
    string Title,
    string? Description,
    string? FilePath,
    int? Line,
    string? Snippet,
    string? SubCategory,
    FindingStatus Status,
    DateTimeOffset FirstSeen);

public sealed record CveRow(
    string AdvisoryId, Severity Severity, string Package, string Version,
    double? Cvss, string? FixedIn, string? ReferenceUrl);

public sealed record CoverageSummary(
    double SequencePercent, int CoveredSequences, int TotalSequences,
    double BranchPercent, int CoveredBranches, int TotalBranches);

public sealed record TestsSummary(
    int Total, int Passed, int Failed, int Skipped, IReadOnlyList<TestSuiteRow> Suites);

public sealed record TestSuiteRow(string Suite, int Failed, int Skipped);

public sealed record LicenseGroup(string License, int Count);

public sealed record StaleComponent(string Name, string Version, string? LatestVersion, int? DaysBehind, bool Stale);

public sealed record ReceiptRow(
    ScannerKind Scanner, string Status, int FindingsCount, DateTimeOffset? CompletedAt, string? ToolName,
    string? ToolVersion = null, string? Notes = null);
