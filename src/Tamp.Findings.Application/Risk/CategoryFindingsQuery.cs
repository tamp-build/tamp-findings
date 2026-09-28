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
                .Where(cv => db.Components.Any(c => c.Id == cv.ComponentId && c.ProjectId == projectId))
                .OrderByDescending(cv => cv.CreatedAt)
                .Select(cv => cv.CommitSha)
                .FirstOrDefaultAsync(ct);
        }
        if (sha is null) return [];

        return await db.ComponentVersions.AsNoTracking()
            .Where(cv => cv.CommitSha == sha
                && db.Components.Any(c => c.Id == cv.ComponentId && c.ProjectId == projectId))
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
