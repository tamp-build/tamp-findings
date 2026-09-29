using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Compliance;

namespace Tamp.Findings.Application.Zt;

// Computes a ZtSystem's Zero Trust coverage (TFND-188 / ADR 0010 §4). Derive-on-read:
// assembles the owned maturity evidence (ztt-posted conformance findings), the
// inheritance edges (with the provider's per-function stage), and the owner picks, then
// runs the pure ZtDispositionResolver + the equal-weight scoring contract. No score is
// stored — it cannot drift from the evidence.
public sealed class ZtScoreQuery(FindingsDbContext db)
{
    /// <summary>The Zero Trust coverage for a project's repo-backed ZtSystem — the entry point
    /// for the per-project maturity dashboard (TFND-199). Resolves the consumer system linked to
    /// the project, then scores it. Null when the project has no linked ZtSystem or no current
    /// ZTMM model is loaded (the client isn't ZT-scored).</summary>
    public async Task<ZtSystemCoverage?> ForProjectAsync(Guid projectId, CancellationToken ct = default)
    {
        var system = await db.ZtSystems.AsNoTracking()
            .Where(s => s.ProjectId == projectId)
            .OrderBy(s => s.CreatedAt)
            .FirstOrDefaultAsync(ct);
        if (system is null) return null;

        var coverage = await ForSystemAsync(system.Id, ct);
        return coverage is null ? null : new ZtSystemCoverage(system.Id, system.Name, system.SystemKind, coverage);
    }

    /// <summary>The coverage for a system, or null when no current ZTMM model is loaded.
    /// A system with no linked project simply has no owned evidence — every function
    /// floors at 1 (the conservative default).</summary>
    public async Task<ZtCoverage?> ForSystemAsync(Guid systemId, CancellationToken ct = default)
    {
        var system = await db.ZtSystems.AsNoTracking().FirstOrDefaultAsync(s => s.Id == systemId, ct);
        if (system is null) return null;

        var model = await db.MaturityModelCatalogs.AsNoTracking().FirstOrDefaultAsync(m => m.IsCurrent, ct);
        if (model is null) return null;

        // Owned maturity evidence: ztt-posted conformance findings (ZtPillar set) for the
        // system's project, most-recent per (pillar, function) so builds don't mix.
        var owned = new List<ZtOwnedEvidence>();
        if (system.ProjectId is { } projectId)
        {
            var cvIds = await db.ComponentVersions.AsNoTracking()
                .Where(v => v.ProjectId == projectId)
                .Select(v => v.Id).ToListAsync(ct);

            var findings = await db.ConformanceFindings.AsNoTracking()
                .Where(f => cvIds.Contains(f.ComponentVersionId) && f.ZtPillar != null && f.ZtFunction != null)
                .OrderByDescending(f => f.EvaluatedAt)
                .ToListAsync(ct);

            owned = findings
                .GroupBy(f => (f.ZtPillar!, f.ZtFunction!), StringTupleComparer.Ordinal)
                .Select(g => g.First())
                .Select(f => new ZtOwnedEvidence(f.ZtPillar!, f.ZtFunction!, f.ZtStage ?? 1,
                    (ZtOwnedVerdict)(int)f.Verdict))
                .ToList();
        }

        // Inheritance edges + the provider's stage per function.
        var edgeRows = await db.ZtInheritanceEdges.AsNoTracking()
            .Where(e => e.SystemId == systemId).ToListAsync(ct);
        var offeringIds = edgeRows.Select(e => e.OfferingId).Distinct().ToList();
        var offerings = await db.EnterpriseOfferings.AsNoTracking()
            .Where(o => offeringIds.Contains(o.Id)).ToListAsync(ct);
        var edges = edgeRows.Select(e =>
        {
            var offering = offerings.FirstOrDefault(o => o.Id == e.OfferingId);
            var score = offering?.FunctionScores.FirstOrDefault(s =>
                string.Equals(s.Pillar, e.Pillar, StringComparison.OrdinalIgnoreCase)
                && string.Equals(s.Function, e.Function, StringComparison.OrdinalIgnoreCase));
            return new ZtEdgeInput(e.Pillar, e.Function, score?.Stage,
                HasStatement: !string.IsNullOrWhiteSpace(e.Statement), e.ExpiresAt);
        }).ToList();

        var picks = (await db.ZtSystemPicks.AsNoTracking().Where(p => p.SystemId == systemId).ToListAsync(ct))
            .Select(p => new ZtPickInput(p.Pillar, p.Function, p.Kind)).ToList();

        return ZtDispositionResolver.Resolve(model, owned, edges, picks, DateTimeOffset.UtcNow);
    }

    // Case-insensitive comparer for the (pillar, function) grouping key.
    private sealed class StringTupleComparer : IEqualityComparer<(string, string)>
    {
        public static readonly StringTupleComparer Ordinal = new();
        public bool Equals((string, string) a, (string, string) b) =>
            string.Equals(a.Item1, b.Item1, StringComparison.OrdinalIgnoreCase)
            && string.Equals(a.Item2, b.Item2, StringComparison.OrdinalIgnoreCase);
        public int GetHashCode((string, string) x) =>
            HashCode.Combine(x.Item1.ToLowerInvariant(), x.Item2.ToLowerInvariant());
    }
}

/// <summary>A project's ZtSystem paired with its derived coverage (TFND-199).</summary>
public sealed record ZtSystemCoverage(Guid SystemId, string SystemName, string? SystemKind, ZtCoverage Coverage);
