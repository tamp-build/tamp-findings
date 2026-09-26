using System.Globalization;
using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Application.Approvals;
using Tamp.Findings.Application.Auditing;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Application.Poam;

/// <summary>
/// What an approved AO-extension request DOES (TFND-119): moves the committed
/// completion date to the one the requester proposed.
///
/// <para>
/// Unlike the other effects, this one needs data the decision itself does not
/// carry — the proposed date. It reads it from <see cref="PendingApproval.Payload"/>
/// (an ISO-8601 date the request wrote there). An extension that moved the date
/// with no recorded reason is the failure this record exists to prevent, so the
/// requester's reason (in <see cref="PendingApproval.Justification"/>) is carried
/// into the audit detail verbatim.
/// </para>
/// <para>
/// Runs inside <see cref="ApprovalService.DecideAsync"/>'s transaction on the
/// shared context; never calls SaveChanges (see <see cref="IApprovalEffect"/>).
/// </para>
/// </summary>
public sealed class PoamExtensionEffect : IApprovalEffect
{
    private readonly FindingsDbContext _db;
    private readonly AuditLog _audit;

    public PoamExtensionEffect(FindingsDbContext db, AuditLog audit)
    {
        _db = db;
        _audit = audit;
    }

    public ApprovalKind Kind => ApprovalKind.PoamExtension;

    public async Task ApplyAsync(PendingApproval approval, Principal decider, CancellationToken ct)
    {
        // No date, no move. A malformed or missing payload means there is nothing
        // to apply — the approval still stands on the record, but a date cannot be
        // invented.
        if (!DateTimeOffset.TryParse(
                approval.Payload, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var newDate))
            return;

        var item = await _db.PoamItems.SingleOrDefaultAsync(p => p.Id == approval.SubjectId, ct);
        // A closed item's date is not something an extension should reopen.
        if (item is null || item.ClosedAt is not null) return;

        var previous = item.ScheduledCompletionDate;
        item.ScheduledCompletionDate = newDate;
        item.UpdatedAt = DateTimeOffset.UtcNow;

        _audit.Record(decider, AuditActions.PoamExtensionRequested, AuditClass.Risk,
            new ScopeTarget(approval.ClientId, approval.ProjectId, null),
            subjectId: item.Id, subjectKind: nameof(PoamItem),
            detail: $"{item.Title}: {Show(previous)} → {Show(newDate)} — approved extension request "
                  + $"from {approval.RequestedByLogin}"
                  + (approval.Justification is { Length: > 0 } why ? $" ({why})" : ""));
    }

    private static string Show(DateTimeOffset? value) =>
        value?.ToString("yyyy-MM-dd") ?? "unscheduled";
}
