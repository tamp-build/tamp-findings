using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Application.Explorer;

/// <summary>
/// The SAST spine's tree and detail.
///
/// Findings run to ~5,000 rows on a large ingest, so the tree is grouped by
/// module and the leaf rows are virtualized by the caller. Nothing here loads
/// finding BODIES for the whole tree — only the counts the tree renders — and
/// the detail is fetched for one selection at a time.
/// </summary>
public sealed class FindingsExplorerQuery
{
    private readonly FindingsDbContext _db;

    public FindingsExplorerQuery(FindingsDbContext db) => _db = db;

    /// <summary>
    /// The tree: files grouped by their top path segment, worst severity first
    /// within each group.
    ///
    /// Grouping by path prefix rather than by scanner is deliberate — a reader
    /// looking for "what is wrong in the API project" thinks in paths, and the
    /// scanner that found it is detail, not structure.
    /// </summary>
    public async Task<IReadOnlyList<FindingGroup>> TreeAsync(
        Guid projectId, string? commitSha, IReadOnlySet<ScannerKind> scanners, CancellationToken ct = default)
    {
        var rows = await (
            from f in _db.Findings.AsNoTracking()
            join cv in _db.ComponentVersions.AsNoTracking() on f.ComponentVersionId equals cv.Id
            join c in _db.Components.AsNoTracking() on cv.ComponentId equals c.Id
            where c.ProjectId == projectId
                  && (commitSha == null || cv.CommitSha == commitSha)
                  && scanners.Contains(f.Scanner)
                  && f.Status == FindingStatus.Open
            select new { f.Id, f.FilePath, f.Severity, f.RuleId, f.Title, f.Line, f.Scanner })
            .ToArrayAsync(ct);

        return rows
            .GroupBy(r => GroupOf(r.FilePath))
            .OrderBy(g => g.Key, StringComparer.Ordinal)
            .Select(g => new FindingGroup(
                g.Key,
                g.GroupBy(r => r.FilePath ?? "(no file)")
                 .Select(files => new FindingLeaf(
                     files.Key,
                     files.Max(r => r.Severity),
                     files.Count()))
                 // Worst first within a group: a reader scanning for criticals
                 // should not have to read past a hundred info rows.
                 .OrderByDescending(l => l.WorstSeverity)
                 .ThenBy(l => l.Path, StringComparer.Ordinal)
                 .ToList()))
            .ToArray();
    }

    /// <summary>Findings for one file, worst first.</summary>
    public async Task<IReadOnlyList<FindingDetail>> DetailAsync(
        Guid projectId, string? commitSha, IReadOnlySet<ScannerKind> scanners, string filePath,
        CancellationToken ct = default)
    {
        var rows = await (
            from f in _db.Findings.AsNoTracking()
            join cv in _db.ComponentVersions.AsNoTracking() on f.ComponentVersionId equals cv.Id
            join c in _db.Components.AsNoTracking() on cv.ComponentId equals c.Id
            where c.ProjectId == projectId
                  && (commitSha == null || cv.CommitSha == commitSha)
                  && scanners.Contains(f.Scanner)
                  && f.Status == FindingStatus.Open
                  && f.FilePath == filePath
            select new FindingDetail(
                f.Id, f.RuleId, f.Severity, f.Title, f.Description, f.Line, f.Scanner))
            .ToArrayAsync(ct);

        return rows
            .OrderByDescending(r => r.Severity)
            .ThenBy(r => r.Line ?? 0)
            .ToArray();
    }

    /// <summary>
    /// The file's source, if this product happens to have it.
    ///
    /// It does NOT store source for SAST. The only full file content in the
    /// database is CoverageSourceFile.SourceText, captured when a coverage
    /// report is ingested — so the source viewer is available for a
    /// SAST-flagged file exactly when coverage also ran over it.
    ///
    /// That is a real limitation the hand-off does not account for, and the
    /// honest response is to show the viewer when the source exists and the
    /// findings table when it does not, rather than pretending to a capability
    /// the ingest contract never had. Storing source for every flagged file
    /// would be a new ingest responsibility and a significant one — it is
    /// worth a ticket, not a silent assumption.
    /// </summary>
    public async Task<string?> SourceAsync(
        Guid projectId, string filePath, CancellationToken ct = default)
    {
        var normalised = filePath.Replace("\\", "/");

        return await (
            from f in _db.CoverageSourceFiles.AsNoTracking()
            join r in _db.CoverageReports.AsNoTracking() on f.CoverageReportId equals r.Id
            join cv in _db.ComponentVersions.AsNoTracking() on r.ComponentVersionId equals cv.Id
            join c in _db.Components.AsNoTracking() on cv.ComponentId equals c.Id
            where c.ProjectId == projectId && f.RelativePath == normalised
            orderby r.Id
            select f.SourceText).FirstOrDefaultAsync(ct);
    }

    // Top path segment. Falls back to a named bucket rather than an empty
    // string, so a finding with no path is visible rather than silently
    // grouped under "".
    private static string GroupOf(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return "(no file)";
        var normalised = path.Replace('\\', '/').TrimStart('.', '/');
        var slash = normalised.IndexOf('/');
        return slash <= 0 ? "(root)" : normalised[..slash];
    }
}

/// <summary>
/// Files under one path prefix.
///
/// Files is a concrete List because Blazor's Virtualize needs an ICollection
/// to know the count without enumerating — and materialising it here, once,
/// is the difference between that and re-materialising on every render, which
/// would defeat the point of virtualizing at all.
/// </summary>
public sealed record FindingGroup(string Name, List<FindingLeaf> Files);

public sealed record FindingLeaf(string Path, Severity WorstSeverity, int Count);

public sealed record FindingDetail(
    Guid Id, string RuleId, Severity Severity, string Title, string? Description, int? Line, ScannerKind Scanner);
