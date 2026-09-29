using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Application.Evidence;

/// <summary>
/// The collected-evidence data behind the evidence-detail pages (v3 §4) for the
/// keys that have no existing page-query of their own: dast, quality, a11y, kev
/// and baseImage. The rest of the keys reuse queries that already exist — poam
/// (PoamQuery), vex (VexQuery), provenance / vdp (SsdfAttestationBuilder and the
/// Project row) — and conformance has no producer until phase 7.
///
/// Scope is resolved the SAME way as CategoryFindingsQuery and the project hub —
/// the requested commit, or the latest canonical build — so the evidence a page
/// lists and the number the hub tile shows come from one set of component
/// versions and cannot disagree.
/// </summary>
public sealed class EvidenceQuery(FindingsDbContext db)
{
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

    // The Findings-table evidence keys: dast (ZAP/Nuclei), quality (Spectral,
    // oasdiff, Stryker, NetArchTest, dependency-cruiser) and a11y (axe-core).
    // Same shape, one method — only the scanner set differs.
    public Task<IReadOnlyList<EvidenceFinding>> DastAsync(Guid projectId, string? commitSha, CancellationToken ct = default)
        => FindingsAsync(projectId, commitSha, ScannerKindsSet.Dast, ct);

    public Task<IReadOnlyList<EvidenceFinding>> QualityAsync(Guid projectId, string? commitSha, CancellationToken ct = default)
        => FindingsAsync(projectId, commitSha, ScannerKindsSet.Quality, ct);

    public Task<IReadOnlyList<EvidenceFinding>> AccessibilityAsync(Guid projectId, string? commitSha, CancellationToken ct = default)
        => FindingsAsync(projectId, commitSha, ScannerKindsSet.Accessibility, ct);

    private async Task<IReadOnlyList<EvidenceFinding>> FindingsAsync(
        Guid projectId, string? commitSha, ScannerKind[] scanners, CancellationToken ct)
    {
        var cvIds = await ResolveCvIdsAsync(projectId, commitSha, ct);
        if (cvIds.Length == 0) return [];

        return await db.Findings.AsNoTracking()
            .Where(f => cvIds.Contains(f.ComponentVersionId) && scanners.Contains(f.Scanner))
            .OrderByDescending(f => f.Severity).ThenBy(f => f.FilePath).ThenBy(f => f.Line)
            .Select(f => new EvidenceFinding(
                f.Scanner, f.Severity, f.RuleId, f.Title, f.FilePath, f.Line, f.Status, f.FirstSeen))
            .ToListAsync(ct);
    }

    /// <summary>The build's CVEs that appear on the CISA KEV catalog, joined from
    /// the SBOM vulnerabilities. Distinct by CVE — one advisory can hit many
    /// components.</summary>
    public async Task<IReadOnlyList<KevRow>> KevAsync(Guid projectId, string? commitSha, CancellationToken ct = default)
    {
        var cvIds = await ResolveCvIdsAsync(projectId, commitSha, ct);
        if (cvIds.Length == 0) return [];

        var rows = await
            (from v in db.Vulnerabilities.AsNoTracking()
             where cvIds.Contains(v.SbomComponent!.SbomSnapshot!.ComponentVersionId)
             join k in db.KevAdvisories.AsNoTracking() on v.AdvisoryId equals k.CveId
             select new KevRow(
                 k.CveId, k.Product, k.VulnerabilityName, k.DateAdded, k.DueDate,
                 k.KnownRansomwareCampaignUse, v.Severity))
            .ToListAsync(ct);

        // Collapse to one row per CVE, keeping the worst severity seen.
        return rows
            .GroupBy(r => r.CveId)
            .Select(g => g.OrderByDescending(r => r.Severity).First())
            .OrderByDescending(r => r.KnownRansomware).ThenBy(r => r.DueDate)
            .ToArray();
    }

    /// <summary>Container images inspected for this build, with base-image age
    /// (measured at build) and OS.</summary>
    public async Task<IReadOnlyList<BaseImageRow>> BaseImagesAsync(Guid projectId, string? commitSha, CancellationToken ct = default)
    {
        var cvIds = await ResolveCvIdsAsync(projectId, commitSha, ct);
        if (cvIds.Length == 0) return [];

        var rows = await db.ContainerImages.AsNoTracking()
            .Where(im => cvIds.Contains(im.ComponentVersionId))
            .Select(im => new
            {
                im.Reference, im.BaseImageReference, im.OsFamily, im.OsVersion,
                im.BaseImageCreatedAt, im.InspectedAt,
            })
            .ToListAsync(ct);

        return rows
            .Select(im =>
            {
                int? age = im.BaseImageCreatedAt is { } created && im.InspectedAt > created
                    ? (int)(im.InspectedAt - created).TotalDays
                    : im.BaseImageCreatedAt is null ? null : 0;
                return new BaseImageRow(im.Reference, im.BaseImageReference, age, im.OsFamily, im.OsVersion);
            })
            .OrderByDescending(r => r.AgeDays ?? -1)
            .ToArray();
    }

    // Local copies of the scanner sets as arrays, so EF can translate Contains.
    private static class ScannerKindsSet
    {
        public static readonly ScannerKind[] Dast = ScannerKinds.Dast.ToArray();
        public static readonly ScannerKind[] Quality = ScannerKinds.Quality.ToArray();
        public static readonly ScannerKind[] Accessibility = ScannerKinds.Accessibility.ToArray();
    }
}

public sealed record EvidenceFinding(
    ScannerKind Scanner, Severity Severity, string RuleId, string Title,
    string? Location, int? Line, FindingStatus Status, DateTimeOffset FirstSeen);

public sealed record KevRow(
    string CveId, string? Product, string? VulnerabilityName,
    DateOnly DateAdded, DateOnly DueDate, bool KnownRansomware, Severity Severity);

public sealed record BaseImageRow(
    string Reference, string? BaseImageReference, int? AgeDays, string? OsFamily, string? OsVersion);
