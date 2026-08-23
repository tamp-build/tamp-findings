using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Application.Risk;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Application.Explorer;

/// <summary>
/// The SBOM spine: dependencies and their known vulnerabilities.
///
/// The tree groups by ECOSYSTEM (nuget, npm, …) because that is how a reader
/// decides who owns a fix — a .NET dependency and a JavaScript one are usually
/// two different people's problem.
///
/// The VEX cell in the detail is the workflow, not decoration: it turns a table
/// into a next action. A CVE with no VEX statement is an unanswered question,
/// and the design colours it accordingly.
/// </summary>
public sealed class SbomExplorerQuery
{
    private readonly FindingsDbContext _db;

    public SbomExplorerQuery(FindingsDbContext db) => _db = db;

    public async Task<IReadOnlyList<SbomGroup>> TreeAsync(
        Guid projectId, string? commitSha, CancellationToken ct = default)
    {
        var components = await (
            from sc in _db.SbomComponents.AsNoTracking()
            join snap in _db.SbomSnapshots.AsNoTracking() on sc.SbomSnapshotId equals snap.Id
            join cv in _db.ComponentVersions.AsNoTracking() on snap.ComponentVersionId equals cv.Id
            join c in _db.Components.AsNoTracking() on cv.ComponentId equals c.Id
            where c.ProjectId == projectId && (commitSha == null || cv.CommitSha == commitSha)
            select new
            {
                sc.Id, sc.Purl, sc.Name, sc.Version, sc.License,
                sc.LatestVersion, sc.LatestReleasedAt, sc.CurrentReleasedAt,
            })
            .ToArrayAsync(ct);

        var ids = components.Select(c => c.Id).ToArray();

        var vulnCounts = await _db.Vulnerabilities.AsNoTracking()
            .Where(v => ids.Contains(v.SbomComponentId))
            .GroupBy(v => v.SbomComponentId)
            .Select(g => new { ComponentId = g.Key, Count = g.Count(), Worst = g.Max(v => v.Severity) })
            .ToArrayAsync(ct);

        var byComponent = vulnCounts.ToDictionary(v => v.ComponentId);

        // TFND-8 (F7.3): which of these cost money.
        //
        // Loaded once and matched in memory. The registry is a handful of rows
        // and the match is a prefix test, so a join would be more machinery for
        // the same answer. Enabled entries only — a shop with a site licence
        // has said it does not want these flagged.
        var registry = await _db.PaidComponents.AsNoTracking()
            .Where(p => p.Enabled)
            .ToArrayAsync(ct);

        return components
            .GroupBy(c => EcosystemOf(c.Purl))
            .OrderBy(g => g.Key, StringComparer.Ordinal)
            .Select(g => new SbomGroup(
                g.Key,
                g.Select(c => new SbomLeaf(
                     c.Name,
                     c.Version,
                     c.Purl,
                     byComponent.TryGetValue(c.Id, out var v) ? v.Worst : null,
                     byComponent.TryGetValue(c.Id, out var v2) ? v2.Count : 0,
                     c.LatestVersion,
                     // TFND-22. Staleness is the gap between when the version
                     // this build SHIPS was released and when the newest one
                     // was — not the age of the dependency. A package released
                     // five years ago and never updated since is CURRENT; one
                     // released last month with a newer release last week is
                     // two weeks behind.
                     StaleDays(c.CurrentReleasedAt, c.LatestReleasedAt),
                     // The vendor, when this line item is a paid seat. Shown on
                     // the row rather than only on the costs view because this
                     // is the screen somebody is on when they decide whether to
                     // keep a dependency, and "this one renews" is part of that
                     // decision.
                     VendorOf(registry, c.Purl, c.Name)))
                 // Vulnerable first, then alphabetical. A reader opening this
                 // spine is looking for what is wrong, not taking inventory.
                 .OrderByDescending(l => l.VulnerabilityCount > 0)
                 .ThenByDescending(l => l.WorstSeverity ?? Severity.Info)
                 .ThenBy(l => l.Name, StringComparer.OrdinalIgnoreCase)
                 .ToList()))
            .ToArray();
    }

    /// <summary>
    /// Known vulnerabilities for one dependency, with KEV listing and VEX
    /// disposition resolved.
    /// </summary>
    public async Task<IReadOnlyList<SbomVulnerability>> DetailAsync(
        Guid projectId, string? commitSha, string purl, CancellationToken ct = default)
    {
        var rows = await (
            from v in _db.Vulnerabilities.AsNoTracking()
            join sc in _db.SbomComponents.AsNoTracking() on v.SbomComponentId equals sc.Id
            join snap in _db.SbomSnapshots.AsNoTracking() on sc.SbomSnapshotId equals snap.Id
            join cv in _db.ComponentVersions.AsNoTracking() on snap.ComponentVersionId equals cv.Id
            join c in _db.Components.AsNoTracking() on cv.ComponentId equals c.Id
            where c.ProjectId == projectId
                  && (commitSha == null || cv.CommitSha == commitSha)
                  && sc.Purl == purl
            select new { v.AdvisoryId, v.Severity, v.Title, v.FixedInVersion, v.Source, v.CvssScore, v.CvssVector, v.ReferenceUrl, sc.Version })
            .ToArrayAsync(ct);

        if (rows.Length == 0) return [];

        var advisoryIds = rows.Select(r => r.AdvisoryId).Distinct().ToArray();

        // KEV: actively exploited in the wild. The single most actionable fact
        // about a CVE, which is why it gets its own solid chip rather than
        // being buried in a description.
        var kev = await _db.KevAdvisories.AsNoTracking()
            .Where(k => advisoryIds.Contains(k.CveId))
            .Select(k => k.CveId)
            .ToArrayAsync(ct);
        var kevSet = kev.ToHashSet(StringComparer.OrdinalIgnoreCase);

        // Statement matching mirrors VexResolver exactly: bare purl on both
        // sides, version compared separately, retired statements ignored. If
        // this drifted from the resolver the table would show a disposition
        // that scoring does not honour — the worst kind of wrong, because it
        // looks answered.
        var bare = VexResolver.StripPurlVersion(purl);
        var version = rows[0].Version;

        var statements = (await _db.VexStatements.AsNoTracking()
            .Where(v => v.ProjectId == projectId
                     && v.RetiredAt == null
                     && advisoryIds.Contains(v.AdvisoryId))
            .Select(v => new { v.AdvisoryId, v.Purl, v.ComponentVersion, v.Status, v.Justification })
            .ToArrayAsync(ct))
            .Where(v => VexResolver.StripPurlVersion(v.Purl) == bare
                        && (v.ComponentVersion is null || v.ComponentVersion == version))
            .ToArray();

        return rows
            .DistinctBy(r => r.AdvisoryId)
            .Select(r =>
            {
                var statement = statements.FirstOrDefault(v => v.AdvisoryId == r.AdvisoryId);
                return new SbomVulnerability(
                    r.AdvisoryId, r.Severity, r.Title, r.FixedInVersion, r.Source,
                    r.CvssScore, r.CvssVector, r.ReferenceUrl,
                    kevSet.Contains(r.AdvisoryId),
                    statement?.Status,
                    statement?.Justification,
                    statement is not null
                        && VexResolver.IsSuppressingStatus(statement.Status, statement.Justification));
            })
            // KEV first regardless of severity: something being exploited today
            // outranks something merely scored higher.
            .OrderByDescending(r => r.KevListed)
            .ThenByDescending(r => r.Severity)
            .ThenBy(r => r.AdvisoryId, StringComparer.Ordinal)
            .ToArray();
    }

    /// <summary>
    /// How far behind the shipped version is, in days, or null when the
    /// registry did not tell us.
    ///
    /// Null is a real and common answer — NuGet's flatcontainer API carries no
    /// release dates at all, so nuget rows have nothing to compare. Rendering
    /// that as "0 days behind" would claim currency this product cannot verify,
    /// which is the same defect as a clean score from a scan that never ran.
    /// </summary>
    /// <summary>
    /// The vendor whose subscription covers this package, or null.
    ///
    /// First match wins. The unique index on (ecosystem, prefix) stops two
    /// entries covering the same packages, so "first" and "only" are the same
    /// thing — and if that ever stopped being true, reporting one vendor is
    /// still better than reporting a package twice on a screen that adds up
    /// costs.
    /// </summary>
    private static string? VendorOf(
        IReadOnlyList<PaidComponent> registry, string purl, string name)
    {
        var ecosystem = EcosystemOf(purl);

        foreach (var entry in registry)
        {
            if (entry.Matches(purl, name, ecosystem)) return entry.Vendor;
        }

        return null;
    }

    private static int? StaleDays(DateTimeOffset? current, DateTimeOffset? latest)
    {
        if (current is not { } shipped || latest is not { } newest) return null;

        var days = (int)(newest - shipped).TotalDays;
        return days > 0 ? days : null;
    }

    // purl is "pkg:type/namespace/name@version". The type is the ecosystem.
    private static string EcosystemOf(string purl)
    {
        const string prefix = "pkg:";
        if (!purl.StartsWith(prefix, StringComparison.Ordinal)) return "(unknown)";

        var rest = purl[prefix.Length..];
        var slash = rest.IndexOf('/');
        return slash <= 0 ? rest : rest[..slash];
    }
}

public sealed record SbomGroup(string Ecosystem, List<SbomLeaf> Components);

public sealed record SbomLeaf(
    string Name, string Version, string Purl, Severity? WorstSeverity, int VulnerabilityCount,
    string? LatestVersion,
    /// <summary>
    /// Days between the shipped version's release and the newest release, or
    /// null when the registry does not publish dates (every NuGet row) or when
    /// this IS the newest.
    /// </summary>
    int? StaleDays,
    /// <summary>
    /// The vendor whose paid subscription covers this package, or null
    /// (TFND-8 / F7.3).
    /// </summary>
    string? PaidVendor = null)
{
    /// <summary>
    /// Behind by more than six months — the threshold the scorer's sbomStaleness
    /// category already uses, so the badge and the score agree about what
    /// "stale" means.
    /// </summary>
    public bool IsStale => StaleDays is > 180;
}

public sealed record SbomVulnerability(
    string AdvisoryId,
    Severity Severity,
    string? Title,
    string? FixedInVersion,
    ScannerKind Source,
    double? CvssScore,
    string? CvssVector,
    string? ReferenceUrl,
    bool KevListed,
    VexStatementStatus? VexStatus,
    VexJustification? VexJustification,
    // Whether the statement actually takes this CVE out of the gating picture.
    // A NotAffected with no justification does NOT, and the table has to say so
    // — otherwise someone writes half a statement and believes they are done.
    bool VexSuppresses);
