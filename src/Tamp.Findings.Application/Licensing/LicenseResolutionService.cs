using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Application.Auditing;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Projects;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Application.Licensing;

/// <summary>
/// The global, purl-keyed license knowledge base (TFND-222).
///
/// A resolution attests WHAT a package version is licensed under when its SBOM
/// carried no resolvable SPDX expression. It is a fact about the artifact, so it
/// is stored once and read by every project that pulls the same purl — both the
/// license category screen and the risk scorer consult it before falling back to
/// "unknown". The legal allow/deny position is a separate, project-layered thing
/// and is unaffected by this.
/// </summary>
public sealed class LicenseResolutionService(
    FindingsDbContext db,
    CapabilityEvaluator capabilities,
    AuditLog audit)
{
    /// <summary>Every resolution as a purl → SPDX map (case-insensitive on purl).</summary>
    public async Task<IReadOnlyDictionary<string, string>> MapAsync(CancellationToken ct = default)
    {
        var rows = await db.LicenseResolutions.AsNoTracking()
            .Select(r => new { r.Purl, r.Spdx }).ToListAsync(ct);
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var r in rows) map[r.Purl] = r.Spdx;   // one row per purl (unique index)
        return map;
    }

    /// <summary>The resolutions themselves, for display/audit on the license screen.</summary>
    public async Task<IReadOnlyList<LicenseResolution>> ListAsync(CancellationToken ct = default) =>
        await db.LicenseResolutions.AsNoTracking().OrderBy(r => r.Purl).ToListAsync(ct);

    /// <summary>
    /// Attest (or re-attest) the license for a package version. Upserts by purl;
    /// re-resolving a purl overwrites the prior attestation and re-stamps the author.
    /// </summary>
    public async Task<Result<Guid>> ResolveAsync(
        Principal actor, string purl, string spdx, string? note, CancellationToken ct = default)
    {
        var decision = capabilities.Evaluate(actor, Capability.EditPolicyWeights);
        if (!decision.Allowed) return Result<Guid>.Denied(decision.Reason!);

        purl = purl?.Trim() ?? "";
        spdx = spdx?.Trim() ?? "";
        if (purl.Length == 0) return Result<Guid>.Invalid("A package-url (purl) is required.");
        if (spdx.Length == 0) return Result<Guid>.Invalid("An SPDX license id is required.");

        var existing = await db.LicenseResolutions.FirstOrDefaultAsync(r => r.Purl == purl, ct);
        if (existing is null)
        {
            existing = new LicenseResolution { Purl = purl, Spdx = spdx };
            db.LicenseResolutions.Add(existing);
        }
        existing.Spdx = spdx;
        existing.Note = string.IsNullOrWhiteSpace(note) ? null : note.Trim();
        existing.ResolvedBy = actor.Login;
        existing.ResolvedAt = DateTimeOffset.UtcNow;

        audit.Record(actor, AuditActions.LicenseResolved, AuditClass.Risk,
            subjectId: existing.Id, subjectKind: "license-resolution",
            detail: $"{purl} → {spdx}");
        await db.SaveChangesAsync(ct);
        return Result<Guid>.Ok(existing.Id);
    }

    /// <summary>Remove a resolution — the purl reverts to whatever its SBOM carried.</summary>
    public async Task<Result<Guid>> ClearAsync(Principal actor, string purl, CancellationToken ct = default)
    {
        var decision = capabilities.Evaluate(actor, Capability.EditPolicyWeights);
        if (!decision.Allowed) return Result<Guid>.Denied(decision.Reason!);

        var existing = await db.LicenseResolutions.FirstOrDefaultAsync(r => r.Purl == purl.Trim(), ct);
        if (existing is null) return Result<Guid>.Invalid("No resolution exists for that package.");

        db.LicenseResolutions.Remove(existing);
        audit.Record(actor, AuditActions.LicenseResolutionCleared, AuditClass.Risk,
            subjectId: existing.Id, subjectKind: "license-resolution", detail: purl);
        await db.SaveChangesAsync(ct);
        return Result<Guid>.Ok(existing.Id);
    }
}
