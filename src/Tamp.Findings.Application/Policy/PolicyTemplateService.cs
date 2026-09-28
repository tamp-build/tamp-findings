using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Application.Approvals;
using Tamp.Findings.Application.Auditing;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Projects;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;
using Tamp.Findings.Domain.Risk;

namespace Tamp.Findings.Application.Policy;

/// <summary>
/// Reads and writes policy templates — the top layer of the three-layer model
/// (ADR 0007). A save that only hardens or leaves the template equal applies
/// directly and bumps the version; a save that would LOOSEN the template lowers
/// the floor for every client and project under it, so it is routed to InfoSec
/// as a <see cref="ApprovalKind.LoosenPolicyTemplate"/> approval and does not
/// take effect until approved.
/// </summary>
public sealed class PolicyTemplateService(
    FindingsDbContext db,
    CapabilityEvaluator capabilities,
    AuditLog audit,
    ApprovalService approvals)
{
    public async Task<IReadOnlyList<PolicyTemplateCard>> LibraryAsync(CancellationToken ct = default)
    {
        var templates = await db.PolicyTemplates.AsNoTracking()
            .OrderBy(t => t.Name).ThenByDescending(t => t.Version)
            .Select(t => new { t.Id, t.Name, t.Version, t.IsSeeded })
            .ToListAsync(ct);

        // How many clients inherit each template — the "used by N clients" count.
        var usage = await db.Clients.AsNoTracking()
            .Where(c => c.PolicyTemplateId != null)
            .GroupBy(c => c.PolicyTemplateId!.Value)
            .Select(g => new { Id = g.Key, Count = g.Count() })
            .ToDictionaryAsync(x => x.Id, x => x.Count, ct);

        return templates
            .Select(t => new PolicyTemplateCard(t.Id, t.Name, t.Version, t.IsSeeded, usage.GetValueOrDefault(t.Id)))
            .ToArray();
    }

    public Task<PolicyTemplate?> LoadAsync(Guid id, CancellationToken ct = default) =>
        db.PolicyTemplates.AsNoTracking().FirstOrDefaultAsync(t => t.Id == id, ct);

    /// <summary>Save a template's overlay. Returns whether it applied immediately
    /// or was routed for approval, plus the specific loosenings when routed.</summary>
    public async Task<Result<TemplateSaveOutcome>> SaveAsync(
        Principal actor, Guid id, PolicyLayer proposed, string? note = null, CancellationToken ct = default)
    {
        var decision = capabilities.Evaluate(actor, Capability.EditPolicyWeights);
        if (!decision.Allowed) return Result<TemplateSaveOutcome>.Denied(decision.Reason!);

        var template = await db.PolicyTemplates.FirstOrDefaultAsync(t => t.Id == id, ct);
        if (template is null) return Result<TemplateSaveOutcome>.Invalid("That template no longer exists.");

        var loosened = PolicyLayerCompare.Loosens(template.Layer, proposed);
        if (loosened.Count > 0)
        {
            // Routed to InfoSec — the proposed overlay rides along in the payload.
            var payload = JsonSerializer.Serialize(proposed);
            var reason = "Loosens " + template.Label + ": " + string.Join("; ", loosened)
                       + (note is { Length: > 0 } ? $" — {note}" : "");
            var req = await approvals.RequestAsync(
                actor, scope: default, ApprovalKind.LoosenPolicyTemplate,
                subjectKind: nameof(PolicyTemplate), subjectId: template.Id,
                justification: reason, payload: payload, ct: ct);

            if (!req.Success)
                return req.WasDenied
                    ? Result<TemplateSaveOutcome>.Denied(req.Error!)
                    : Result<TemplateSaveOutcome>.Invalid(req.Error!);

            return Result<TemplateSaveOutcome>.Ok(new TemplateSaveOutcome(TemplateSaveStatus.PendingApproval, req.Value, loosened));
        }

        // Harden-or-equal: applies now, version bumped.
        template.Layer = proposed;
        template.Version += 1;
        template.UpdatedAt = DateTimeOffset.UtcNow;
        audit.Record(actor, AuditActions.PolicyTemplateSaved, AuditClass.Risk,
            subjectId: template.Id, subjectKind: nameof(PolicyTemplate),
            detail: $"{template.Name} → v{template.Version} (hardened or equal)");
        await db.SaveChangesAsync(ct);

        return Result<TemplateSaveOutcome>.Ok(new TemplateSaveOutcome(TemplateSaveStatus.Applied, template.Id, []));
    }
}

public sealed record PolicyTemplateCard(Guid Id, string Name, int Version, bool IsSeeded, int UsedByClients);

public enum TemplateSaveStatus { Applied, PendingApproval }

public sealed record TemplateSaveOutcome(TemplateSaveStatus Status, Guid Id, IReadOnlyList<string> Loosened);
