using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Application.Auditing;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Projects;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Risk;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Application.Risk;

/// <summary>
/// The org's own entries on the unauthorized-component list (CM-8(3), TFND-211). Feed-synced entries are
/// maintained by the sync service; this is the hand-authored half. Changing the list changes what every
/// project's SBOM is judged against, so it is gated like policy weights and audited as a Risk action.
/// </summary>
public sealed class BannedComponentService(FindingsDbContext db, CapabilityEvaluator capabilities, AuditLog audit)
{
    public const string ManualSource = "manual";

    public async Task<IReadOnlyList<BannedComponent>> ListAsync(int take = 200, string? search = null, CancellationToken ct = default)
    {
        var q = db.BannedComponents.AsNoTracking().AsQueryable();
        if (!string.IsNullOrWhiteSpace(search))
        {
            var s = search.Trim().ToLowerInvariant();
            q = q.Where(b => b.Purl.Contains(s));
        }
        return await q.OrderBy(b => b.Source != ManualSource).ThenByDescending(b => b.UpdatedAt).Take(take).ToListAsync(ct);
    }

    public async Task<(int Manual, int Feed, DateTimeOffset? LastSynced)> CountsAsync(CancellationToken ct = default) =>
        (await db.BannedComponents.CountAsync(b => b.Active && b.Source == ManualSource, ct),
         await db.BannedComponents.CountAsync(b => b.Active && b.Source != ManualSource, ct),
         await db.BannedComponents.Where(b => b.Source != ManualSource).MaxAsync(b => (DateTimeOffset?)b.UpdatedAt, ct));

    public async Task<Result<BannedComponent>> AddAsync(
        Principal actor, string purl, IEnumerable<string>? versions, string? reason, CancellationToken ct = default)
    {
        var decision = capabilities.Evaluate(actor, Capability.EditPolicyWeights);
        if (!decision.Allowed) return Result<BannedComponent>.Denied(decision.Reason!);

        var key = BannedComponentMatcher.Key(purl);
        if (key is null) return Result<BannedComponent>.Invalid("That is not a package url (expected pkg:<type>/<name>, e.g. pkg:npm/left-pad).");
        if (string.IsNullOrWhiteSpace(reason)) return Result<BannedComponent>.Invalid("A reason is required.");

        var vers = (versions ?? []).Select(v => v.Trim()).Where(v => v.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var existing = await db.BannedComponents.FirstOrDefaultAsync(b => b.Purl == key && b.Source == ManualSource, ct);
        if (existing is null)
        {
            existing = new BannedComponent { Purl = key, Source = ManualSource, Kind = BannedComponentKind.Banned };
            db.BannedComponents.Add(existing);
        }
        existing.Versions = vers;
        existing.Reason = reason.Trim();
        existing.Active = true;
        existing.AddedByLogin = actor.Login;
        existing.UpdatedAt = DateTimeOffset.UtcNow;

        audit.Record(actor, "banned_component.added", AuditClass.Risk, ScopeTarget.Instance,
            subjectKind: nameof(BannedComponent), detail: $"{key} ({(vers.Count == 0 ? "all versions" : string.Join(", ", vers))}): {existing.Reason}");
        await db.SaveChangesAsync(ct);
        return Result<BannedComponent>.Ok(existing);
    }

    public async Task<Result<bool>> RemoveAsync(Principal actor, Guid id, CancellationToken ct = default)
    {
        var decision = capabilities.Evaluate(actor, Capability.EditPolicyWeights);
        if (!decision.Allowed) return Result<bool>.Denied(decision.Reason!);

        var row = await db.BannedComponents.FirstOrDefaultAsync(b => b.Id == id, ct);
        if (row is null) return Result<bool>.Invalid("That entry no longer exists.");

        // A feed row is deactivated, not deleted: the next sync would otherwise re-add it. A manual
        // entry is simply removed.
        if (row.Source == ManualSource) db.BannedComponents.Remove(row);
        else { row.Active = false; row.UpdatedAt = DateTimeOffset.UtcNow; }

        audit.Record(actor, "banned_component.removed", AuditClass.Risk, ScopeTarget.Instance,
            subjectKind: nameof(BannedComponent), detail: $"{row.Purl} ({row.Source}{(row.SourceId is null ? "" : " " + row.SourceId)})");
        await db.SaveChangesAsync(ct);
        return Result<bool>.Ok(true);
    }
}
