using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Application.Approvals;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Auditing;
using Tamp.Findings.Application.Projects;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;
using Tamp.Findings.Domain.Risk;

namespace Tamp.Findings.Application.Policy;

/// <summary>
/// The client layer of the three-layer policy (ADR 0007): the template a client
/// inherits and its own hardening on top.
///
/// Hardening the client's own overlay applies directly (a lower layer may add or
/// tighten freely, and validation refuses anything that would loosen the
/// inherited template). SWITCHING the template swaps the whole inherited
/// baseline, so it is routed to InfoSec as a
/// <see cref="ApprovalKind.SwitchClientTemplate"/> approval.
/// </summary>
public sealed class ClientPolicyService(
    FindingsDbContext db,
    CapabilityEvaluator capabilities,
    AuditLog audit,
    ApprovalService approvals)
{
    /// <summary>Save the client's own hardening overlay. Refuses a change that
    /// would loosen the inherited template (a client can only add or tighten).</summary>
    public async Task<Result<Guid>> SaveHardeningAsync(
        Principal actor, Guid clientId, PolicyLayer proposed, CancellationToken ct = default)
    {
        var decision = capabilities.Evaluate(actor, Capability.EditPolicyWeights);
        if (!decision.Allowed) return Result<Guid>.Denied(decision.Reason!);

        var client = await db.Clients.FirstOrDefaultAsync(c => c.Id == clientId, ct);
        if (client is null) return Result<Guid>.Invalid("That client no longer exists.");

        // The overlay may only harden what the template already imposes.
        var inherited = await InheritedTemplateLayerAsync(client, ct);
        if (inherited is not null)
        {
            var loosened = PolicyLayerCompare.Loosens(inherited, proposed);
            if (loosened.Count > 0)
                return Result<Guid>.Invalid(
                    "A client can only harden its template, not loosen it: " + string.Join("; ", loosened)
                    + ". Loosening the baseline is a template change and needs InfoSec approval.");
        }

        client.PolicyLayer = proposed;
        audit.Record(actor, AuditActions.ClientPolicySaved, AuditClass.Risk,
            new ScopeTarget(clientId, null, null),
            subjectId: clientId, subjectKind: nameof(Client),
            detail: $"{client.Name}: client policy hardening saved");
        await db.SaveChangesAsync(ct);
        return Result<Guid>.Ok(clientId);
    }

    /// <summary>Request switching the client's inherited template. Always routes
    /// to InfoSec — it replaces the baseline every project under the client
    /// inherits.</summary>
    public async Task<Result<Guid>> RequestTemplateSwitchAsync(
        Principal actor, Guid clientId, Guid newTemplateId, string? note = null, CancellationToken ct = default)
    {
        var decision = capabilities.Evaluate(actor, Capability.EditPolicyWeights);
        if (!decision.Allowed) return Result<Guid>.Denied(decision.Reason!);

        var client = await db.Clients.AsNoTracking().FirstOrDefaultAsync(c => c.Id == clientId, ct);
        if (client is null) return Result<Guid>.Invalid("That client no longer exists.");
        if (client.PolicyTemplateId == newTemplateId)
            return Result<Guid>.Invalid("The client already inherits that template.");

        var template = await db.PolicyTemplates.AsNoTracking().FirstOrDefaultAsync(t => t.Id == newTemplateId, ct);
        if (template is null) return Result<Guid>.Invalid("That template no longer exists.");

        var reason = $"Switch {client.Name} to {template.Label}"
                   + (note is { Length: > 0 } ? $" — {note}" : "");
        return await approvals.RequestAsync(
            actor, new ScopeTarget(clientId, null, null), ApprovalKind.SwitchClientTemplate,
            subjectKind: nameof(Client), subjectId: clientId,
            justification: reason, payload: newTemplateId.ToString(), ct: ct);
    }

    private async Task<PolicyLayer?> InheritedTemplateLayerAsync(Client client, CancellationToken ct)
    {
        if (client.PolicyTemplateId is not { } tid) return null;
        var template = await db.PolicyTemplates.AsNoTracking().FirstOrDefaultAsync(t => t.Id == tid, ct);
        return template?.Layer;
    }
}
