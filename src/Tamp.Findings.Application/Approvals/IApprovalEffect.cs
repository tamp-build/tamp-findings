using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Application.Approvals;

/// <summary>
/// The domain consequence of an approval being APPROVED (TFND-117).
///
/// <para>
/// <see cref="ApprovalService.DecideAsync"/> is deliberately generic — it owns
/// the decision (who may decide, the self-approval guard, the audit entry) but
/// knows nothing about POA&amp;M, VEX or attestations. The consequence of a
/// <em>yes</em> lives here, one implementation per <see cref="ApprovalKind"/>,
/// so a new approval kind adds an effect rather than a branch inside the
/// decision service.
/// </para>
/// <para>
/// This is the link the Elsa design never actually had: the workflow (removed in
/// ADR 0005 / TFND-164) only handled expiry, and nothing ever transitioned the
/// subject when a request was approved. An approved risk acceptance whose POA&amp;M
/// stayed Open was the gap.
/// </para>
/// </summary>
public interface IApprovalEffect
{
    /// <summary>Which decision this effect applies to.</summary>
    ApprovalKind Kind { get; }

    /// <summary>
    /// Apply the consequence of the approval.
    ///
    /// <para>
    /// Called by <see cref="ApprovalService.DecideAsync"/> ONLY on approval,
    /// AFTER the approval row is flipped to Approved and BEFORE the single
    /// <c>SaveChanges</c>. The effect shares the same scoped
    /// <c>FindingsDbContext</c>, so its mutation commits atomically with the
    /// decision — an effect MUST NOT call <c>SaveChanges</c> itself, or the two
    /// stop being one transaction and a crash between them leaves an approved
    /// decision with an untouched subject.
    /// </para>
    /// <para>
    /// <paramref name="decider"/> is the person who approved — the holder of the
    /// kind's decider capability — so an effect that transitions the subject
    /// acts under real authority, not the system's.
    /// </para>
    /// </summary>
    Task ApplyAsync(PendingApproval approval, Principal decider, CancellationToken ct);
}
