using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Application.Auditing;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Projects;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Application.Approvals;

/// <summary>
/// Pending decisions (TFND-116).
///
/// ONE representation, used by POA&amp;M, VEX and attestation alike. The
/// hand-off's requirement is a grammar rather than three features: "a POA&amp;M
/// awaiting risk-acceptance approval is neither Open nor Risk accepted". Three
/// separate pending flags would have produced three slightly different answers
/// to the same question.
///
/// This deliberately does NOT depend on Elsa. The engine orchestrates; these
/// rows are what the screens read, and the product has to work with the engine
/// switched off — a pending decision that vanishes when a worker is down is
/// worse than no workflow at all.
/// </summary>
public sealed class ApprovalService
{
    private readonly FindingsDbContext _db;
    private readonly CapabilityEvaluator _capabilities;
    private readonly AuditLog _audit;

    public ApprovalService(FindingsDbContext db, CapabilityEvaluator capabilities, AuditLog audit)
    {
        _db = db;
        _capabilities = capabilities;
        _audit = audit;
    }

    /// <summary>
    /// The capability a decider needs for each kind.
    ///
    /// Here rather than at each call site so "who may approve a risk
    /// acceptance?" has exactly one answer. AcceptRisk is InfoSec only and
    /// notably NOT Admin — that absence is load-bearing.
    /// </summary>
    public static Capability DeciderCapability(ApprovalKind kind) => kind switch
    {
        ApprovalKind.PoamRiskAcceptance => Capability.AcceptRisk,
        ApprovalKind.PoamCompletion => Capability.CompletePoamItem,
        ApprovalKind.PoamExtension => Capability.CreatePoamItem,
        ApprovalKind.VexPublication => Capability.PublishVex,
        ApprovalKind.AttestationSignOff => Capability.ExportAttestation,
        _ => Capability.ManageIngestKey,
    };

    /// <summary>
    /// Ask for a decision.
    ///
    /// Refuses a second request for the same subject and kind: a pending item
    /// cannot have its terminal action triggered twice, and two live requests
    /// for one decision would let two people approve the same thing.
    /// </summary>
    public async Task<Result<Guid>> RequestAsync(
        Principal actor, ScopeTarget scope, ApprovalKind kind,
        string subjectKind, Guid subjectId, string? justification = null,
        Guid? assignedTo = null, CancellationToken ct = default)
    {
        // Requesting is not deciding. The requester needs to be able to ACT on
        // the subject at all — otherwise anyone could flood a queue — but not
        // to hold the capability they are asking someone else to exercise.
        var decision = _capabilities.Evaluate(actor, Capability.ViewEvidence);
        if (!decision.Allowed) return Result<Guid>.Denied(decision.Reason!);

        var existing = await _db.PendingApprovals.AnyAsync(
            a => a.SubjectKind == subjectKind && a.SubjectId == subjectId
              && a.Kind == kind && a.State == ApprovalState.Pending, ct);
        if (existing)
            return Result<Guid>.Invalid("That decision has already been requested and is still pending.");

        var approval = new PendingApproval
        {
            Kind = kind,
            SubjectKind = subjectKind,
            SubjectId = subjectId,
            ClientId = scope.ClientId,
            ProjectId = scope.ProjectId,
            RequestedByUserId = actor.UserId,
            RequestedByLogin = actor.Login,
            Justification = string.IsNullOrWhiteSpace(justification) ? null : justification.Trim(),
            AssignedToUserId = assignedTo,
        };
        _db.PendingApprovals.Add(approval);

        _audit.Record(actor, "approval.requested", AuditClass.Risk, scope,
            subjectId: subjectId, subjectKind: subjectKind,
            detail: $"{kind} requested{(assignedTo is null ? "" : " of a named approver")}"
                  + (approval.Justification is null ? "" : $" — {approval.Justification}"));

        await _db.SaveChangesAsync(ct);
        return Result<Guid>.Ok(approval.Id);
    }

    /// <summary>
    /// Approve or reject.
    ///
    /// The capability check is on the KIND, not on the caller's own guess. A
    /// transport that resolved the approval and then decided for itself who may
    /// take it would eventually disagree with this table.
    /// </summary>
    public async Task<Result<ApprovalState>> DecideAsync(
        Principal actor, Guid approvalId, bool approve, string? note = null,
        CancellationToken ct = default)
    {
        var approval = await _db.PendingApprovals.SingleOrDefaultAsync(a => a.Id == approvalId, ct);
        if (approval is null)
            return Result<ApprovalState>.Invalid("That approval no longer exists.");

        // The second-approval guard, and the reason a pending state is a row
        // rather than a computed flag: two people racing the same decision
        // would otherwise both succeed.
        if (approval.State != ApprovalState.Pending)
            return Result<ApprovalState>.Invalid(
                $"This was already {approval.State.ToString().ToLowerInvariant()} "
                + $"by {approval.DecidedByLogin} on {approval.DecidedAt:yyyy-MM-dd}.");

        var scope = new ScopeTarget(approval.ClientId, approval.ProjectId, null);
        var decision = _capabilities.Evaluate(actor, DeciderCapability(approval.Kind));
        if (!decision.Allowed) return Result<ApprovalState>.Denied(decision.Reason!);

        // A named assignee is a real assignment, not a hint. Someone else
        // holding the capability cannot quietly take it instead — the record
        // has to say who was asked and who answered, and those being different
        // people is a fact worth surfacing rather than hiding.
        if (approval.AssignedToUserId is { } assignee && assignee != actor.UserId)
            return Result<ApprovalState>.Denied("This decision was assigned to someone else.");

        // Nobody approves their own request. The whole point of routing a risk
        // acceptance through an approval is that a second person looks at it.
        if (approval.RequestedByUserId == actor.UserId)
            return Result<ApprovalState>.Denied(
                "You requested this decision. Approving your own request would make the approval "
                + "a formality rather than a control.");

        approval.State = approve ? ApprovalState.Approved : ApprovalState.Rejected;
        approval.DecidedByUserId = actor.UserId;
        approval.DecidedByLogin = actor.Login;
        approval.DecidedAt = DateTimeOffset.UtcNow;
        approval.DecisionNote = string.IsNullOrWhiteSpace(note) ? null : note.Trim();

        _audit.Record(actor, approve ? "approval.approved" : "approval.rejected",
            AuditClass.Risk, scope,
            subjectId: approval.SubjectId, subjectKind: approval.SubjectKind,
            detail: $"{approval.Kind} requested by {approval.RequestedByLogin}"
                  + (approval.DecisionNote is null ? "" : $" — {approval.DecisionNote}"));

        await _db.SaveChangesAsync(ct);
        return Result<ApprovalState>.Ok(approval.State);
    }

    /// <summary>
    /// Withdraw a request. Not a rejection — nobody said no.
    /// </summary>
    public async Task<Result<bool>> CancelAsync(
        Principal actor, Guid approvalId, CancellationToken ct = default)
    {
        var approval = await _db.PendingApprovals.SingleOrDefaultAsync(a => a.Id == approvalId, ct);
        if (approval is null) return Result<bool>.Ok(false);
        if (approval.State != ApprovalState.Pending) return Result<bool>.Ok(false);

        if (approval.RequestedByUserId != actor.UserId)
        {
            var decision = _capabilities.Evaluate(actor, DeciderCapability(approval.Kind));
            if (!decision.Allowed)
                return Result<bool>.Denied("Only the requester or an approver can withdraw this.");
        }

        approval.State = ApprovalState.Cancelled;
        approval.DecidedByUserId = actor.UserId;
        approval.DecidedByLogin = actor.Login;
        approval.DecidedAt = DateTimeOffset.UtcNow;

        _audit.Record(actor, "approval.cancelled", AuditClass.Risk,
            new ScopeTarget(approval.ClientId, approval.ProjectId, null),
            subjectId: approval.SubjectId, subjectKind: approval.SubjectKind,
            detail: $"{approval.Kind} withdrawn");

        await _db.SaveChangesAsync(ct);
        return Result<bool>.Ok(true);
    }

    /// <summary>
    /// Is this subject waiting on a decision, and which one.
    ///
    /// The screens call this to render the pending qualifier and to disable the
    /// actions that would race the workflow.
    /// </summary>
    public async Task<PendingState?> ForSubjectAsync(
        string subjectKind, Guid subjectId, CancellationToken ct = default)
    {
        var approval = await _db.PendingApprovals.AsNoTracking()
            .Where(a => a.SubjectKind == subjectKind && a.SubjectId == subjectId
                     && a.State == ApprovalState.Pending)
            .OrderByDescending(a => a.RequestedAt)
            .FirstOrDefaultAsync(ct);

        return approval is null ? null : Describe(approval);
    }

    /// <summary>Pending states for a whole page's worth of subjects, in one query.</summary>
    public async Task<IReadOnlyDictionary<Guid, PendingState>> ForSubjectsAsync(
        string subjectKind, IReadOnlyCollection<Guid> subjectIds, CancellationToken ct = default)
    {
        if (subjectIds.Count == 0) return new Dictionary<Guid, PendingState>();

        var approvals = await _db.PendingApprovals.AsNoTracking()
            .Where(a => a.SubjectKind == subjectKind
                     && subjectIds.Contains(a.SubjectId)
                     && a.State == ApprovalState.Pending)
            .ToArrayAsync(ct);

        return approvals
            .GroupBy(a => a.SubjectId)
            .ToDictionary(g => g.Key, g => Describe(g.OrderByDescending(a => a.RequestedAt).First()));
    }

    /// <summary>
    /// What is waiting on this person.
    ///
    /// "Anything awaiting THIS user shows up as an action, not a notification"
    /// — so this is the source for a filter on an existing table, never for a
    /// separate inbox screen.
    ///
    /// Driven by REAL ASSIGNMENT and not by role alone: a named assignee counts
    /// only for that person, and an unassigned request counts only for those
    /// who actually hold the capability at its scope. A filter that matched on
    /// role alone would put every InfoSec officer's name on every decision and
    /// teach all of them to ignore it.
    /// </summary>
    public async Task<IReadOnlyList<AwaitingRow>> AwaitingAsync(
        Principal actor, Func<ScopeTarget, Task<Principal?>> resolveAt, CancellationToken ct = default)
    {
        var pending = await _db.PendingApprovals.AsNoTracking()
            .Where(a => a.State == ApprovalState.Pending)
            .Where(a => a.AssignedToUserId == null || a.AssignedToUserId == actor.UserId)
            // Never your own request: you cannot decide it, so it is not
            // waiting on you.
            .Where(a => a.RequestedByUserId != actor.UserId)
            .OrderBy(a => a.RequestedAt)
            .ToArrayAsync(ct);

        var rows = new List<AwaitingRow>(pending.Length);
        foreach (var approval in pending)
        {
            if (approval.AssignedToUserId is null)
            {
                // Unassigned: resolve the actor AT THIS APPROVAL'S SCOPE and
                // ask the matrix. Roles resolve per-scope, so a capability held
                // on one project says nothing about another.
                var atScope = await resolveAt(new ScopeTarget(approval.ClientId, approval.ProjectId, null));
                if (atScope is null) continue;
                if (!_capabilities.Evaluate(atScope, DeciderCapability(approval.Kind)).Allowed) continue;
            }

            rows.Add(new AwaitingRow(
                approval.Id, approval.Kind, approval.SubjectKind, approval.SubjectId,
                approval.ProjectId, approval.RequestedByLogin, approval.RequestedAt,
                approval.Justification, approval.AssignedToUserId is not null));
        }

        return rows;
    }

    private static PendingState Describe(PendingApproval approval) => new(
        approval.Id,
        approval.Kind,
        approval.RequestedByLogin,
        approval.RequestedAt,
        approval.Justification,
        approval.AssignedToUserId,
        // The qualifier the design asks for: rendered in monospace beside the
        // terminal-status chip, not instead of it.
        Qualifier(approval.Kind));

    private static string Qualifier(ApprovalKind kind) => kind switch
    {
        ApprovalKind.PoamRiskAcceptance => "pending risk acceptance",
        ApprovalKind.PoamCompletion => "pending completion approval",
        ApprovalKind.PoamExtension => "pending AO extension",
        ApprovalKind.VexPublication => "pending publication",
        ApprovalKind.AttestationSignOff => "pending sign-off",
        _ => "pending approval",
    };
}

/// <summary>
/// A subject's pending decision, as the screens render it.
///
/// <see cref="Qualifier"/> sits BESIDE the terminal-status chip in monospace,
/// never in place of it: an item awaiting risk acceptance is still Open, and
/// showing it as Risk accepted would state the outcome of a decision nobody has
/// taken.
/// </summary>
public sealed record PendingState(
    Guid ApprovalId,
    ApprovalKind Kind,
    string RequestedBy,
    DateTimeOffset RequestedAt,
    string? Justification,
    Guid? AssignedToUserId,
    string Qualifier);

public sealed record AwaitingRow(
    Guid ApprovalId, ApprovalKind Kind, string SubjectKind, Guid SubjectId,
    Guid? ProjectId, string RequestedBy, DateTimeOffset RequestedAt,
    string? Justification, bool AssignedToYouByName);
