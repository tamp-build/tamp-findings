using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Application.Explorer;

/// <summary>
/// Findings grouped by RULE rather than by path (TFND-18).
///
/// The explorer's SAST spine groups by path, which answers "which files are bad"
/// — and that is the right first question. It does not answer "what is wrong
/// with this codebase", and with SonarAnalyzer's ~470 rules plus Roslynator's
/// ~500 the difference matters: eleven S2094s and four S6966s look identical in
/// a severity count and are two completely different pieces of work.
///
/// One is "delete some empty classes". The other is a real API misuse. A view
/// that cannot tell them apart cannot help anyone decide what to fix first.
/// </summary>
public sealed class RuleBreakdownQuery
{
    private readonly FindingsDbContext _db;

    public RuleBreakdownQuery(FindingsDbContext db) => _db = db;

    /// <summary>
    /// Rules on a build, worst-and-most-common first.
    ///
    /// <paramref name="scanners"/> narrows to one class of finding — the SAST
    /// set, the DAST set — because mixing a Roslyn rule and a ZAP alert in one
    /// ranked list invites comparing counts that mean different things.
    /// </summary>
    public async Task<IReadOnlyList<RuleRow>> ByRuleAsync(
        Guid projectId, string? commitSha, IReadOnlySet<ScannerKind> scanners,
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
            select new { f.RuleId, f.Severity, f.Scanner, f.Title, f.FilePath })
            .ToArrayAsync(ct);

        return rows
            .GroupBy(f => f.RuleId, StringComparer.Ordinal)
            .Select(g =>
            {
                var files = g.Where(f => f.FilePath is { Length: > 0 })
                             .GroupBy(f => f.FilePath!, StringComparer.Ordinal)
                             .OrderByDescending(f => f.Count())
                             .ToArray();

                return new RuleRow(
                    g.Key,
                    // The rule's own title, from whichever finding carries it.
                    // A rule id alone is unreadable — nobody knows what S6966
                    // is — and the scanner already told us.
                    g.Select(f => f.Title).FirstOrDefault(t => !string.IsNullOrWhiteSpace(t)) ?? g.Key,
                    g.Max(f => f.Severity),
                    g.Select(f => f.Scanner).First(),
                    g.Count(),
                    files.Length,
                    // Where it bites hardest. A rule with 40 hits in one file
                    // is a different problem from one with 40 hits across 40
                    // files: the first is usually one bad pattern, the second
                    // is a habit.
                    files.FirstOrDefault()?.Key,
                    files.FirstOrDefault()?.Count() ?? 0);
            })
            // Worst severity first, then by count. Ordering by count alone
            // would put 200 style nits above a single critical.
            .OrderByDescending(r => r.WorstSeverity)
            .ThenByDescending(r => r.Count)
            .ThenBy(r => r.RuleId, StringComparer.Ordinal)
            .ToArray();
    }
}

public sealed record RuleRow(
    string RuleId,
    string Title,
    Severity WorstSeverity,
    ScannerKind Scanner,
    int Count,
    int FileCount,
    /// <summary>The file this rule fires in most, or null when the rule has no file.</summary>
    string? TopFilePath,
    int TopFileCount)
{
    /// <summary>
    /// Concentrated in one place rather than spread across the codebase.
    ///
    /// Worth surfacing because it changes what the fix is: a rule firing 40
    /// times in one file is usually one bad pattern to correct once; the same
    /// count across 40 files is a habit, and correcting it is a different
    /// conversation.
    /// </summary>
    public bool Concentrated => FileCount > 0 && TopFileCount * 2 >= Count;
}
