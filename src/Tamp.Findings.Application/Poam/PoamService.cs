using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Application.Auditing;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Projects;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Application.Poam;

/// <summary>
/// Creating, editing and closing POA&amp;M items (TFND-97 / TFND-98).
///
/// Every mutation checks the capability HERE rather than trusting the caller,
/// and writes its audit entry in the same transaction (ADR 0002). For POA&amp;M
/// that matters more than usual: the audit trail IS the deliverable an
/// Authorizing Official reads, so an unaudited transition is not a missing log
/// line, it is a gap in the federal record.
/// </summary>
public sealed class PoamService
{
    private readonly FindingsDbContext _db;
    private readonly CapabilityEvaluator _capabilities;
    private readonly AuditLog _audit;

    public PoamService(FindingsDbContext db, CapabilityEvaluator capabilities, AuditLog audit)
    {
        _db = db;
        _capabilities = capabilities;
        _audit = audit;
    }

    public async Task<Result<Guid>> CreateAsync(
        Principal actor, ScopeTarget scope, Guid projectId, PoamDraft draft, CancellationToken ct = default)
    {
        var decision = _capabilities.Evaluate(actor, Capability.CreatePoamItem);
        if (!decision.Allowed) return Result<Guid>.Denied(decision.Reason!);

        if (Validate(draft) is { } invalid) return Result<Guid>.Invalid(invalid);

        var item = new PoamItem
        {
            ProjectId = projectId,
            Title = draft.Title.Trim(),
            WeaknessDescription = draft.WeaknessDescription.Trim(),
            MitigationPlan = Blank(draft.MitigationPlan),
            ResourcesRequired = Blank(draft.ResourcesRequired),
            ReferenceUrl = Blank(draft.ReferenceUrl),
            Severity = draft.Severity,
            Status = draft.Status,
            ScheduledCompletionDate = draft.ScheduledCompletionDate,
            LinkedFindingIds = draft.LinkedFindingIds.Distinct().ToList(),
            AuthorUserId = actor.UserId,
        };

        // A brand new item can be created straight into a terminal state; the
        // stamps have to follow or the row would read as live forever.
        StampTerminal(item, item.Status);

        _db.PoamItems.Add(item);

        _audit.Record(actor, "poam.created", AuditClass.Risk, scope,
            subjectId: item.Id, subjectKind: nameof(PoamItem), detail: item.Title);

        await _db.SaveChangesAsync(ct);
        return Result<Guid>.Ok(item.Id);
    }

    public async Task<Result<Guid>> UpdateAsync(
        Principal actor, ScopeTarget scope, Guid projectId, Guid itemId, PoamDraft draft,
        CancellationToken ct = default)
    {
        var decision = _capabilities.Evaluate(actor, Capability.CreatePoamItem);
        if (!decision.Allowed) return Result<Guid>.Denied(decision.Reason!);

        if (Validate(draft) is { } invalid) return Result<Guid>.Invalid(invalid);

        var item = await _db.PoamItems.SingleOrDefaultAsync(
            p => p.Id == itemId && p.ProjectId == projectId, ct);
        if (item is null) return Result<Guid>.Invalid("That POA&M item no longer exists.");

        // Status changes go through TransitionAsync, which enforces the two
        // capabilities the matrix separates out. Letting the edit dialog write
        // Status directly would route around both.
        if (draft.Status != item.Status)
            return Result<Guid>.Invalid("Change the status from the record view, not the edit dialog.");

        item.Title = draft.Title.Trim();
        item.WeaknessDescription = draft.WeaknessDescription.Trim();
        item.MitigationPlan = Blank(draft.MitigationPlan);
        item.ResourcesRequired = Blank(draft.ResourcesRequired);
        item.ReferenceUrl = Blank(draft.ReferenceUrl);
        item.Severity = draft.Severity;
        item.ScheduledCompletionDate = draft.ScheduledCompletionDate;
        item.LinkedFindingIds = draft.LinkedFindingIds.Distinct().ToList();
        item.UpdatedAt = DateTimeOffset.UtcNow;

        _audit.Record(actor, "poam.updated", AuditClass.Risk, scope,
            subjectId: item.Id, subjectKind: nameof(PoamItem), detail: item.Title);

        await _db.SaveChangesAsync(ct);
        return Result<Guid>.Ok(item.Id);
    }

    /// <summary>
    /// Move an item to a new status.
    ///
    /// Two capabilities, not one: <see cref="Capability.AcceptRisk"/> is an
    /// Authorizing Official decision that Admin deliberately does NOT hold,
    /// while completing is ordinary team work. Collapsing them would hand every
    /// Admin the AO's signature.
    /// </summary>
    public async Task<Result<PoamStatus>> TransitionAsync(
        Principal actor, ScopeTarget scope, Guid projectId, Guid itemId, PoamStatus target,
        CancellationToken ct = default)
    {
        var capability = target switch
        {
            PoamStatus.RiskAccepted => Capability.AcceptRisk,
            PoamStatus.Completed => Capability.CompletePoamItem,
            _ => Capability.CreatePoamItem,
        };

        var decision = _capabilities.Evaluate(actor, capability);
        if (!decision.Allowed) return Result<PoamStatus>.Denied(decision.Reason!);

        var item = await _db.PoamItems.SingleOrDefaultAsync(
            p => p.Id == itemId && p.ProjectId == projectId, ct);
        if (item is null) return Result<PoamStatus>.Invalid("That POA&M item no longer exists.");

        if (item.Status == target) return Result<PoamStatus>.Ok(target);

        var previous = item.Status;
        item.Status = target;
        item.UpdatedAt = DateTimeOffset.UtcNow;
        StampTerminal(item, target);

        var action = target switch
        {
            PoamStatus.RiskAccepted => AuditActions.PoamRiskAccepted,
            PoamStatus.Completed => AuditActions.PoamCompleted,
            _ => "poam.status_changed",
        };

        _audit.Record(actor, action, AuditClass.Risk, scope,
            subjectId: item.Id, subjectKind: nameof(PoamItem),
            detail: $"{item.Title}: {previous} → {target}");

        await _db.SaveChangesAsync(ct);
        return Result<PoamStatus>.Ok(target);
    }

    /// <summary>
    /// Move the committed date out, with the AO's reason recorded.
    ///
    /// The reason is REQUIRED and goes in the audit detail. An extension with
    /// no stated reason is indistinguishable from someone quietly making a
    /// past-due item stop being past due, which is the failure this whole
    /// record exists to prevent.
    /// </summary>
    public async Task<Result<DateTimeOffset>> RequestExtensionAsync(
        Principal actor, ScopeTarget scope, Guid projectId, Guid itemId,
        DateTimeOffset newDate, string reason, CancellationToken ct = default)
    {
        var decision = _capabilities.Evaluate(actor, Capability.CreatePoamItem);
        if (!decision.Allowed) return Result<DateTimeOffset>.Denied(decision.Reason!);

        reason = reason.Trim();
        if (reason.Length == 0)
            return Result<DateTimeOffset>.Invalid("An extension needs a reason the AO can read.");

        var item = await _db.PoamItems.SingleOrDefaultAsync(
            p => p.Id == itemId && p.ProjectId == projectId, ct);
        if (item is null) return Result<DateTimeOffset>.Invalid("That POA&M item no longer exists.");

        var previous = item.ScheduledCompletionDate;
        item.ScheduledCompletionDate = newDate;
        item.UpdatedAt = DateTimeOffset.UtcNow;

        _audit.Record(actor, AuditActions.PoamExtensionRequested, AuditClass.Risk, scope,
            subjectId: item.Id, subjectKind: nameof(PoamItem),
            detail: $"{item.Title}: {Show(previous)} → {Show(newDate)} — {reason}");

        await _db.SaveChangesAsync(ct);
        return Result<DateTimeOffset>.Ok(newDate);
    }

    /// <summary>
    /// Permanent deletion.
    ///
    /// The UI steers hard away from this — federal practice is to CANCEL an
    /// item, because a deleted one leaves no trail for the AO. It stays
    /// available for entries genuinely opened in error, and it writes an audit
    /// entry carrying the title, so the record shows that something existed
    /// even after the row is gone.
    /// </summary>
    public async Task<Result<bool>> DeleteAsync(
        Principal actor, ScopeTarget scope, Guid projectId, Guid itemId, CancellationToken ct = default)
    {
        var decision = _capabilities.Evaluate(actor, Capability.CreatePoamItem);
        if (!decision.Allowed) return Result<bool>.Denied(decision.Reason!);

        var item = await _db.PoamItems.SingleOrDefaultAsync(
            p => p.Id == itemId && p.ProjectId == projectId, ct);
        if (item is null) return Result<bool>.Ok(false);

        _db.PoamItems.Remove(item);

        _audit.Record(actor, AuditActions.PoamDeleted, AuditClass.Risk, scope,
            subjectId: item.Id, subjectKind: nameof(PoamItem),
            detail: $"{item.Title} (status {item.Status}, opened {Show(item.CreatedAt)})");

        await _db.SaveChangesAsync(ct);
        return Result<bool>.Ok(true);
    }

    private static void StampTerminal(PoamItem item, PoamStatus status)
    {
        var terminal = status is PoamStatus.Completed or PoamStatus.RiskAccepted or PoamStatus.Cancelled;
        var now = DateTimeOffset.UtcNow;

        item.ClosedAt = terminal ? item.ClosedAt ?? now : null;
        // ActualCompletionDate means "the weakness was remediated". Risk
        // acceptance and cancellation close the item WITHOUT remediating it,
        // so neither stamps it — an AO reading a completion date is entitled to
        // read it as work done.
        item.ActualCompletionDate = status == PoamStatus.Completed ? item.ActualCompletionDate ?? now : null;
    }

    private static string? Validate(PoamDraft draft)
    {
        if (draft.Title.Trim().Length == 0) return "A POA&M item needs a title.";
        if (draft.WeaknessDescription.Trim().Length == 0)
            return "The federal template requires a weakness description.";
        if (draft.ReferenceUrl is { Length: > 0 } url
            && !Uri.TryCreate(url.Trim(), UriKind.Absolute, out _))
            return "The reference needs to be a full URL.";
        return null;
    }

    private static string? Blank(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    private static string Show(DateTimeOffset? value) =>
        value?.ToString("yyyy-MM-dd") ?? "unscheduled";
}

/// <summary>
/// What the create/edit dialog collects. The federal POA&amp;M template fields,
/// plus the links back to the findings that motivated the item.
/// </summary>
public sealed record PoamDraft(
    string Title,
    string WeaknessDescription,
    string? MitigationPlan,
    string? ResourcesRequired,
    string? ReferenceUrl,
    Severity Severity,
    PoamStatus Status,
    DateTimeOffset? ScheduledCompletionDate,
    IReadOnlyList<Guid> LinkedFindingIds);
