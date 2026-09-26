using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Application.Approvals;
using Tamp.Findings.Application.Auditing;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Application.Poam;

/// <summary>
/// What an approved completion request DOES (TFND-118): closes the POA&amp;M as
/// Completed.
///
/// <para>
/// Closing a federal record should not be a scanner's silence becoming somebody's
/// signature — a person decides. This effect is that decision taking hold: the
/// approver (holding <see cref="Capability.CompletePoamItem"/> by construction)
/// confirms the remediation, and the item closes as genuinely done.
/// </para>
/// <para>
/// Runs inside <see cref="ApprovalService.DecideAsync"/>'s transaction on the
/// shared context; never calls SaveChanges (see <see cref="IApprovalEffect"/>).
/// </para>
/// </summary>
public sealed class PoamCompletionEffect : IApprovalEffect
{
    private readonly FindingsDbContext _db;
    private readonly AuditLog _audit;

    public PoamCompletionEffect(FindingsDbContext db, AuditLog audit)
    {
        _db = db;
        _audit = audit;
    }

    public ApprovalKind Kind => ApprovalKind.PoamCompletion;

    public async Task ApplyAsync(PendingApproval approval, Principal decider, CancellationToken ct)
    {
        var item = await _db.PoamItems.SingleOrDefaultAsync(p => p.Id == approval.SubjectId, ct);
        if (item is null || item.Status == PoamStatus.Completed) return;

        var previous = item.Status;
        var now = DateTimeOffset.UtcNow;
        item.Status = PoamStatus.Completed;
        item.UpdatedAt = now;
        // Completed means the weakness was remediated, so both stamps land — an
        // AO reading a completion date is entitled to read it as work done.
        item.ClosedAt ??= now;
        item.ActualCompletionDate ??= now;

        _audit.Record(decider, AuditActions.PoamCompleted, AuditClass.Risk,
            new ScopeTarget(approval.ClientId, approval.ProjectId, null),
            subjectId: item.Id, subjectKind: nameof(PoamItem),
            detail: $"{item.Title}: {previous} → Completed — approved completion request "
                  + $"from {approval.RequestedByLogin}"
                  + (approval.Justification is { Length: > 0 } why ? $" ({why})" : ""));
    }
}
