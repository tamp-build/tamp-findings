using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Compliance;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Application.Compliance;

// Computes the review-gated conformance roll-up for a build (TFND-191 / ADR 0006) that
// feeds the adrConformance gate. Human-first: a finding counts toward a block ONLY when
// it is undispositioned, its RULE is Reviewed (Draft never blocks), and — for a Semantic
// verdict — adversarially verify-Confirmed. This is where the "advisory preview →
// blocker after review" line is actually enforced.
public sealed class ConformanceGateQuery(FindingsDbContext db)
{
    public async Task<ConformanceSummary> ForBuildAsync(
        Guid projectId, IReadOnlyList<Guid> cvIds, DateTimeOffset asOf, CancellationToken ct = default)
    {
        if (cvIds.Count == 0) return new ConformanceSummary(0, 0, 0);

        var findings = await db.ConformanceFindings.AsNoTracking()
            .Where(f => cvIds.Contains(f.ComponentVersionId))
            .ToListAsync(ct);
        if (findings.Count == 0) return new ConformanceSummary(0, 0, 0);

        // Reviewed rules for this project, keyed by (adrRef, ruleId). Only a Reviewed
        // rule can turn its verdict into a blocker.
        var reviewed = (await db.ConformanceRules.AsNoTracking()
                .Where(r => r.ProjectId == projectId && r.RetiredAt == null && r.ReviewStatus == ReviewStatus.Reviewed)
                .Select(r => new { r.AdrRef, r.RuleId })
                .ToListAsync(ct))
            .Select(r => (r.AdrRef, r.RuleId))
            .ToHashSet(RuleKeyComparer.Ordinal);

        int fails = 0, unknowns = 0;
        foreach (var f in findings)
        {
            if (f.Verdict == ConformanceVerdict.Pass) continue;
            // Accepted deviation (VEX) that hasn't expired → does not block.
            if (f.Dispositioned && (f.DispositionExpiry is null || f.DispositionExpiry > asOf)) continue;
            // Only reviewed rules block.
            if (!reviewed.Contains((f.AdrRef, f.RuleId))) continue;
            // A semantic model claim must be adversarially verify-confirmed to block
            // (ADR 0006): an unconfirmed semantic verdict is not admissible as a blocker.
            if (f.Method == ConformanceMethod.Semantic && f.VerifyVerdict != VerifyOutcome.Confirmed) continue;

            if (f.Verdict == ConformanceVerdict.Fail) fails++;
            else unknowns++;   // Unknown / Error — a non-answer blocks in enforcing (ADR 0006 §6)
        }

        return new ConformanceSummary(findings.Count, fails, unknowns);
    }

    private sealed class RuleKeyComparer : IEqualityComparer<(string, string)>
    {
        public static readonly RuleKeyComparer Ordinal = new();
        public bool Equals((string, string) a, (string, string) b) =>
            string.Equals(a.Item1, b.Item1, StringComparison.OrdinalIgnoreCase)
            && string.Equals(a.Item2, b.Item2, StringComparison.OrdinalIgnoreCase);
        public int GetHashCode((string, string) x) =>
            HashCode.Combine(x.Item1.ToLowerInvariant(), x.Item2.ToLowerInvariant());
    }
}
