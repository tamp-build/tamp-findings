using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Application.Risk;

public sealed record StalenessExemption(Guid VexId, string BarePurl, string? Version, VexJustification Justification, string? Rationale);

// TFND-226. An active NotAffected+justified VEX statement on the reserved STALENESS advisory
// exempts a component from sbomStaleness. Keyed by purl (+ optional exact version), so it
// survives SBOM re-ingest; a version bump re-flags unless the statement is version-bare.
public static class StalenessExemptions
{
    public static async Task<IReadOnlyList<StalenessExemption>> LoadAsync(
        FindingsDbContext db, Guid projectId, CancellationToken ct)
    {
        var rows = await db.VexStatements.AsNoTracking()
            .Where(v => v.ProjectId == projectId
                     && v.RetiredAt == null
                     && v.AdvisoryId == VexStatement.StalenessAdvisoryId
                     && v.Status == VexStatementStatus.NotAffected
                     && v.Justification != null && v.Justification != VexJustification.None)
            .Select(v => new { v.Id, v.Purl, v.ComponentVersion, v.Justification, v.ImpactStatement })
            .ToListAsync(ct);
        return rows.Select(v => new StalenessExemption(
            v.Id, VexResolver.StripPurlVersion(v.Purl), v.ComponentVersion, v.Justification!.Value, v.ImpactStatement)).ToArray();
    }

    public static StalenessExemption? Match(IReadOnlyList<StalenessExemption> exemptions, string purl, string version)
    {
        if (exemptions.Count == 0) return null;
        var bare = VexResolver.StripPurlVersion(purl);
        return exemptions.FirstOrDefault(e => e.BarePurl == bare && (e.Version is null || e.Version == version));
    }
}
