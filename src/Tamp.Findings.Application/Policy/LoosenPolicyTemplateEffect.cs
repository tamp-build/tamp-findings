using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Application.Approvals;
using Tamp.Findings.Application.Auditing;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;
using Tamp.Findings.Domain.Risk;

namespace Tamp.Findings.Application.Policy;

/// <summary>
/// What an approved template-loosening DOES (ADR 0007 §4): applies the proposed
/// overlay carried in the approval payload and bumps the template version. The
/// InfoSec approver holds <see cref="Capability.AcceptRisk"/> by construction —
/// that is the decider capability for <see cref="ApprovalKind.LoosenPolicyTemplate"/>
/// — so the floor is lowered under a real Authorizing Official's authority.
///
/// Runs inside <see cref="ApprovalService.DecideAsync"/>'s transaction on the
/// shared context, so it never calls SaveChanges.
/// </summary>
public sealed class LoosenPolicyTemplateEffect(FindingsDbContext db, AuditLog audit) : IApprovalEffect
{
    public ApprovalKind Kind => ApprovalKind.LoosenPolicyTemplate;

    public async Task ApplyAsync(PendingApproval approval, Principal decider, CancellationToken ct)
    {
        var template = await db.PolicyTemplates.SingleOrDefaultAsync(t => t.Id == approval.SubjectId, ct);
        if (template is null || approval.Payload is not { Length: > 0 } payload) return;

        PolicyLayer? proposed;
        try { proposed = JsonSerializer.Deserialize<PolicyLayer>(payload); }
        catch (JsonException) { return; }
        if (proposed is null) return;

        template.Layer = proposed;
        template.Version += 1;
        template.UpdatedAt = DateTimeOffset.UtcNow;

        audit.Record(decider, AuditActions.PolicyTemplateLoosened, AuditClass.Risk,
            subjectId: template.Id, subjectKind: nameof(PolicyTemplate),
            detail: $"{template.Name} → v{template.Version}: approved loosening requested by "
                  + $"{approval.RequestedByLogin}"
                  + (approval.Justification is { Length: > 0 } why ? $" ({why})" : ""));
    }
}
