using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Application.Approvals;
using Tamp.Findings.Application.Auditing;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Application.Poam;

/// <summary>
/// What an approved risk-acceptance request DOES (TFND-117): moves its POA&amp;M
/// to Risk accepted.
///
/// <para>
/// This is the second person's signature taking effect. The approver holds
/// <see cref="Capability.AcceptRisk"/> by construction — that is the decider
/// capability for <see cref="ApprovalKind.PoamRiskAcceptance"/> — so the
/// transition happens under a real Authorizing Official's authority, and the
/// requester (who does not need that capability) never touches the terminal
/// state themselves.
/// </para>
/// <para>
/// Runs inside <see cref="ApprovalService.DecideAsync"/>'s transaction on the
/// shared context, so it never calls SaveChanges (see <see cref="IApprovalEffect"/>).
/// </para>
/// </summary>
public sealed class PoamRiskAcceptanceEffect : IApprovalEffect
{
    private readonly FindingsDbContext _db;
    private readonly AuditLog _audit;

    public PoamRiskAcceptanceEffect(FindingsDbContext db, AuditLog audit)
    {
        _db = db;
        _audit = audit;
    }

    public ApprovalKind Kind => ApprovalKind.PoamRiskAcceptance;

    public async Task ApplyAsync(PendingApproval approval, Principal decider, CancellationToken ct)
    {
        var item = await _db.PoamItems.SingleOrDefaultAsync(p => p.Id == approval.SubjectId, ct);

        // The subject may have been deleted, or already closed by another path,
        // between the request and the decision. Approving is still valid — the
        // decision stands on the record — but there is nothing left to move, and
        // silently re-opening or re-stamping a closed item would be worse than
        // doing nothing.
        if (item is null || item.Status == PoamStatus.RiskAccepted) return;

        var previous = item.Status;
        item.Status = PoamStatus.RiskAccepted;
        item.UpdatedAt = DateTimeOffset.UtcNow;
        // Risk acceptance closes the item WITHOUT remediating it, so ClosedAt is
        // stamped but ActualCompletionDate is not — an AO reading a completion
        // date is entitled to read it as work done, and this was not.
        item.ClosedAt ??= DateTimeOffset.UtcNow;

        _audit.Record(decider, AuditActions.PoamRiskAccepted, AuditClass.Risk,
            new ScopeTarget(approval.ClientId, approval.ProjectId),
            subjectId: item.Id, subjectKind: nameof(PoamItem),
            detail: $"{item.Title}: {previous} → RiskAccepted — approved risk-acceptance request "
                  + $"from {approval.RequestedByLogin}"
                  + (approval.Justification is { Length: > 0 } why ? $" ({why})" : ""));
    }
}
