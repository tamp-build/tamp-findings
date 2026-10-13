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

    /// <summary>
    /// The approval subject id for one component's exemption (TFND-225).
    ///
    /// Derived from (project, bare purl, version) rather than random, because
    /// ApprovalService refuses a second pending request for the same subject and kind
    /// and that guard is the thing stopping two people filing two exemptions for one
    /// component and a second approver rubber-stamping the duplicate. A random id, as
    /// the VEX publication request uses, silently opts out of it.
    ///
    /// The hash is SHA-256 truncated to the 16 bytes a Guid holds. It is a
    /// hash-to-128-bits function here, not a security primitive — the input is a purl
    /// the caller already knows and the output is a database key — but SHA-256 costs
    /// nothing over MD5 here and avoids leaving a broken-hash call site for someone to
    /// find later and have to reason about.
    /// </summary>
    public static Guid SubjectId(Guid projectId, string barePurl, string? version)
    {
        var key = $"{projectId:N}|{barePurl}|{version ?? "*"}";
        var hash = System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(key));
        return new Guid(hash.AsSpan(0, 16));
    }

    public static StalenessExemption? Match(IReadOnlyList<StalenessExemption> exemptions, string purl, string version)
    {
        if (exemptions.Count == 0) return null;
        var bare = VexResolver.StripPurlVersion(purl);
        return exemptions.FirstOrDefault(e => e.BarePurl == bare && (e.Version is null || e.Version == version));
    }
}
