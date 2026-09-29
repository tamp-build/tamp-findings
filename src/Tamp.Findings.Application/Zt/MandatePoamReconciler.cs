using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Application.Policy;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Application.Zt;

// Wires mandate failures into the shared POA&M model (TFND-189 / ADR 0010 §7, §9). A
// failing or unproven operational/supply-chain mandate is a real POA&M, not a low
// reading — the fail-closed discipline: "didn't run" ≠ "compliant". For each latest
// mandate result on a project that is Fail or Unknown, ensure ONE open POA&M exists
// (SourceKind by lane, SourceRef = mandateId, severity from the pack, ScheduledCompletion
// from the effective PolicyLayer.PoamDeadlineDays window, stamped with the mandate-pack
// version for point-in-time defence). Idempotent — never duplicates an open item.
// Closure stays human-owned (as with LinkedFindings), so a now-passing mandate does not
// auto-close its POA&M; it stops re-creating one.
public sealed class MandatePoamReconciler(FindingsDbContext db, PolicyResolver resolver)
{
    public sealed record CreatedPoam(string MandateId, Guid PoamId, string Title, Domain.Values.Severity Severity);

    public async Task<IReadOnlyList<CreatedPoam>> ReconcileAsync(
        Guid projectId, Guid authorUserId, CancellationToken ct = default)
    {
        var pack = await db.MandatePacks.AsNoTracking().FirstOrDefaultAsync(p => p.IsCurrent, ct);
        if (pack is null) return [];
        var defByMandate = pack.Mandates.ToDictionary(m => m.MandateId, StringComparer.OrdinalIgnoreCase);

        // Latest mandate result per mandateId for the project's builds.
        var cvIds = await db.ComponentVersions.AsNoTracking()
            .Where(v => v.Component!.ProjectId == projectId).Select(v => v.Id).ToListAsync(ct);
        if (cvIds.Count == 0) return [];

        var results = await db.ConformanceFindings.AsNoTracking()
            .Where(f => cvIds.Contains(f.ComponentVersionId) && f.MandateId != null)
            .OrderByDescending(f => f.EvaluatedAt)
            .ToListAsync(ct);
        var latest = results
            .GroupBy(f => f.MandateId!, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.First())
            .ToList();
        if (latest.Count == 0) return [];

        // Review-gate (TFND-192): human-first applies to the tracking axis too. A mandate
        // verdict only raises a POA&M when its RULE is Reviewed — a Draft/heuristic mandate
        // tag is not yet a vetted mapping, so raising a dated POA&M off it is extraction
        // noise. Once a human reviews the mapping, the existing fail-closed behavior stands.
        // Same discipline as the adrConformance block gate (TFND-191).
        var reviewed = (await db.ConformanceRules.AsNoTracking()
                .Where(r => r.ProjectId == projectId && r.RetiredAt == null && r.ReviewStatus == ReviewStatus.Reviewed)
                .Select(r => new { r.AdrRef, r.RuleId })
                .ToListAsync(ct))
            .Select(r => (r.AdrRef, r.RuleId))
            .ToHashSet(RuleKeyComparer.Ordinal);

        // Existing open mandate POA&Ms on this project, keyed by mandate ref.
        var openRefs = await db.PoamItems.AsNoTracking()
            .Where(p => p.ProjectId == projectId && p.ClosedAt == null
                && (p.SourceKind == PoamSource.OperationalMandate || p.SourceKind == PoamSource.SupplyChainMandate)
                && p.SourceRef != null)
            .Select(p => p.SourceRef!)
            .ToListAsync(ct);
        var openSet = openRefs.ToHashSet(StringComparer.OrdinalIgnoreCase);

        // The effective per-severity deadline window (strictest across the policy layers).
        var layer = await resolver.ForProjectAsync(projectId, ct);
        var now = DateTimeOffset.UtcNow;
        var created = new List<CreatedPoam>();

        foreach (var r in latest)
        {
            // A mandate is met only on Pass; Fail and Unknown both raise a POA&M.
            if (r.Verdict == Domain.Compliance.ConformanceVerdict.Pass
                || r.Verdict == Domain.Compliance.ConformanceVerdict.Error) continue;
            // Only a Reviewed mandate mapping is fail-closed (TFND-192).
            if (!reviewed.Contains((r.AdrRef, r.RuleId))) continue;
            if (openSet.Contains(r.MandateId!)) continue; // already tracked

            var def = defByMandate.GetValueOrDefault(r.MandateId!);
            var severity = def?.PoamSeverity ?? Domain.Values.Severity.Medium;
            var title = def?.Title ?? r.MandateId!;
            var sourceKind = def?.Tool == MandateTool.Findings
                ? PoamSource.SupplyChainMandate : PoamSource.OperationalMandate;

            DateTimeOffset? scheduled = null;
            if (layer.PoamDeadlineDays.TryGetValue(severity.ToString(), out var days))
                scheduled = now.AddDays(days.Value);

            var poam = new PoamItem
            {
                ProjectId = projectId,
                Title = $"Mandate not met: {title}",
                WeaknessDescription =
                    $"The '{r.MandateId}' mandate is {r.Verdict} on the latest build "
                    + $"({(r.Verdict == Domain.Compliance.ConformanceVerdict.Unknown ? "unproven — the check did not run" : "failed")}). "
                    + "Under fail-closed enforcement an unproven or failed mandate is a POA&M, not a passing result.",
                Severity = severity,
                Status = PoamStatus.Open,
                SourceKind = sourceKind,
                SourceRef = r.MandateId,
                MandatePackVersion = pack.Version,
                ScheduledCompletionDate = scheduled,
                AuthorUserId = authorUserId,
                LinkedFindingIds = [],
            };
            db.PoamItems.Add(poam);
            openSet.Add(r.MandateId!);
            created.Add(new CreatedPoam(r.MandateId!, poam.Id, poam.Title, severity));
        }

        if (created.Count > 0) await db.SaveChangesAsync(ct);
        return created;
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
