using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Application.Risk;

/// <summary>
/// Cross-source collapse for findings the same analyzer raised twice — SonarQube's server-side C# analysis IS
/// SonarAnalyzer, so `csharpsquid:S2325` (server) and bare `S2325` (local Roslyn) are one issue. Both rows are
/// kept as provenance; only scoring and lists collapse. Key = (file, line, normalized rule id); the
/// SonarQube row is canonical, the Roslyn twin is the duplicate.
/// </summary>
public static class FindingDedupe
{
    private static readonly ScannerKind[] Overlapping = [ScannerKind.SonarQube, ScannerKind.Roslyn];

    public static string NormalizeRuleId(string ruleId)
    {
        var i = ruleId.LastIndexOf(':');
        return i >= 0 ? ruleId[(i + 1)..] : ruleId;
    }

    /// <summary>Ids of rows that duplicate a canonical row from another source on the same builds.</summary>
    public static async Task<HashSet<Guid>> DuplicateIdsAsync(FindingsDbContext db, IReadOnlyCollection<Guid> cvIds, CancellationToken ct)
    {
        var rows = await db.Findings.AsNoTracking()
            .Where(f => cvIds.Contains(f.ComponentVersionId) && Overlapping.Contains(f.Scanner)
                && f.FilePath != null && f.Line != null)
            .Select(f => new { f.Id, f.ComponentVersionId, f.Scanner, f.FilePath, f.Line, f.RuleId })
            .ToListAsync(ct);

        var dupes = new HashSet<Guid>();
        foreach (var g in rows.GroupBy(r => (r.ComponentVersionId, r.FilePath, r.Line, Rule: NormalizeRuleId(r.RuleId))))
        {
            if (g.Select(r => r.Scanner).Distinct().Count() < 2) continue;
            foreach (var r in g.Where(r => r.Scanner != ScannerKind.SonarQube)) dupes.Add(r.Id);
        }
        return dupes;
    }
}
