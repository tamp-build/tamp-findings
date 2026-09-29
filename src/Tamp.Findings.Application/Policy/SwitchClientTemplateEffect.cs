using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Application.Approvals;
using Tamp.Findings.Application.Auditing;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Application.Policy;

/// <summary>
/// What an approved template switch DOES (ADR 0007 §4): points the client at the
/// new template carried (as its id) in the approval payload, swapping the
/// baseline every project under the client inherits. Runs inside the decision's
/// transaction — no SaveChanges.
/// </summary>
public sealed class SwitchClientTemplateEffect(FindingsDbContext db, AuditLog audit) : IApprovalEffect
{
    public ApprovalKind Kind => ApprovalKind.SwitchClientTemplate;

    public async Task ApplyAsync(PendingApproval approval, Principal decider, CancellationToken ct)
    {
        var client = await db.Clients.SingleOrDefaultAsync(c => c.Id == approval.SubjectId, ct);
        if (client is null || !Guid.TryParse(approval.Payload, out var newTemplateId)) return;

        // The template may have been deleted between request and decision.
        var exists = await db.PolicyTemplates.AnyAsync(t => t.Id == newTemplateId, ct);
        if (!exists) return;

        var previous = client.PolicyTemplateId;
        client.PolicyTemplateId = newTemplateId;

        audit.Record(decider, AuditActions.ClientTemplateSwitched, AuditClass.Risk,
            new ScopeTarget(client.Id, null),
            subjectId: client.Id, subjectKind: nameof(Client),
            detail: $"{client.Name}: template {previous?.ToString() ?? "none"} → {newTemplateId} — "
                  + $"approved switch requested by {approval.RequestedByLogin}");
    }
}
