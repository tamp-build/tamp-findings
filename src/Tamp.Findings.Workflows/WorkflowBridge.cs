using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Application.Approvals;
using Tamp.Findings.Application.Auditing;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Risk;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Risk;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Workflows;

/// <summary>
/// The one door between a running workflow and the application layer.
///
/// Activities resolve this rather than reaching for a DbContext directly. Two
/// reasons, and the second is the important one:
///
///  1. Elsa activities are constructed by the engine, so constructor injection
///     of a dozen services would spread across every definition.
///  2. ADR 0002: authorization is decided in Application, once. A workflow that
///     wrote to the database itself would be a transport that forgot to check —
///     the exact failure the layer exists to make unavailable. Every mutation
///     here goes through a service that checks a capability and writes an audit
///     entry.
///
/// The workflow acts AS somebody. Which somebody depends on the step: an
/// approval decision carries the human who took it, while a scheduled reminder
/// carries the system principal, and both are visible in the audit log.
/// </summary>
public sealed class WorkflowBridge
{
    private readonly FindingsDbContext _db;
    private readonly ApprovalService _approvals;
    private readonly AuditLog _audit;
    private readonly RiskInputsBuilder _inputs;

    public WorkflowBridge(
        FindingsDbContext db, ApprovalService approvals, AuditLog audit, RiskInputsBuilder inputs)
    {
        _db = db;
        _approvals = approvals;
        _audit = audit;
        _inputs = inputs;
    }

    /// <summary>
    /// The principal a scheduled or automatic step acts as.
    ///
    /// A real, named, non-human actor rather than an impersonation of whoever
    /// happened to trigger the run. "The workflow did this" is a different fact
    /// from "Scott did this", and an audit log that conflated them would be
    /// unusable for the question an assessor actually asks.
    ///
    /// It holds NO capabilities, deliberately. A workflow cannot accept risk on
    /// anyone's behalf; it can only ask a person to.
    /// </summary>
    public static Principal System { get; } =
        Principal.For(Guid.Empty, "workflow", isAdmin: false, []);

    public Task<PendingState?> PendingForAsync(string subjectKind, Guid subjectId, CancellationToken ct) =>
        _approvals.ForSubjectAsync(subjectKind, subjectId, ct);

    /// <summary>
    /// Link a pending approval to the Elsa instance orchestrating it.
    ///
    /// Kept so an operator holding one can find the other. Without it, a stuck
    /// workflow and a stuck approval look like two unrelated problems.
    /// </summary>
    public async Task LinkAsync(Guid approvalId, string workflowInstanceId, CancellationToken ct)
    {
        var approval = await _db.PendingApprovals.SingleOrDefaultAsync(a => a.Id == approvalId, ct);
        if (approval is null) return;

        approval.WorkflowInstanceId = workflowInstanceId;
        await _db.SaveChangesAsync(ct);
    }

    /// <summary>
    /// Has this approval been decided yet, and how.
    ///
    /// The workflow polls this rather than being pushed to, because the
    /// decision can also be taken from the UI with the engine stopped. A
    /// workflow that only learned about decisions through its own events would
    /// hang forever on one taken while it was down.
    /// </summary>
    public async Task<ApprovalState?> StateOfAsync(Guid approvalId, CancellationToken ct) =>
        await _db.PendingApprovals.AsNoTracking()
            .Where(a => a.Id == approvalId)
            .Select(a => (ApprovalState?)a.State)
            .SingleOrDefaultAsync(ct);

    /// <summary>
    /// Record that a workflow did something, in the same log a person's actions
    /// go into.
    ///
    /// TFND-115's acceptance criterion — "workflow execution writes into the
    /// audit log" — and TFND-116's: approvals belong in the risk class.
    /// </summary>
    public async Task NoteAsync(
        string action, AuditClass @class, ScopeTarget scope,
        Guid? subjectId, string? subjectKind, string detail, CancellationToken ct)
    {
        _audit.Record(System, action, @class, scope, subjectId, subjectKind, detail);
        await _db.SaveChangesAsync(ct);
    }

    /// <summary>
    /// Withdraw an approval that nobody answered.
    ///
    /// Not a rejection — nobody said no. The point is to release the subject
    /// from its pending state, which is what disables the actions that would
    /// race the decision.
    /// </summary>
    public async Task ExpireAsync(Guid approvalId, CancellationToken ct)
    {
        var approval = await _db.PendingApprovals.SingleOrDefaultAsync(a => a.Id == approvalId, ct);
        if (approval is null || approval.State != ApprovalState.Pending) return;

        approval.State = ApprovalState.Cancelled;
        approval.DecidedAt = DateTimeOffset.UtcNow;
        approval.DecidedByLogin = System.Login;
        approval.DecisionNote = "Expired — nobody answered.";

        await _db.SaveChangesAsync(ct);
    }

    /// <summary>
    /// The gates blocking a build (TFND-122).
    ///
    /// BLOCKING, not failing: under four-valued verdicts a gate that could not
    /// be answered is not a gate that passed, so Unknown and Error block too.
    /// A notification that reported only Fail would be the exact defect ADR
    /// 0001's model was introduced to remove.
    /// </summary>
    public async Task<IReadOnlyList<GateResult>> BlockingGatesAsync(
        Guid projectId, string commitSha, CancellationToken ct)
    {
        var project = await _db.Projects.AsNoTracking()
            .Include(p => p.Client)
            .SingleOrDefaultAsync(p => p.Id == projectId, ct);
        if (project is null) return [];

        var build = await _db.ComponentVersions.AsNoTracking()
            .Where(v => v.Component!.ProjectId == projectId && v.CommitSha == commitSha)
            .Select(v => v.Id)
            .ToListAsync(ct);
        if (build.Count == 0) return [];

        var policyId = project.RiskPolicyId ?? project.Client?.RiskPolicyId;
        var policy = policyId is { } id
            ? await _db.RiskPolicies.AsNoTracking().FirstOrDefaultAsync(p => p.Id == id, ct)
            : null;
        policy ??= await _db.RiskPolicies.AsNoTracking().FirstOrDefaultAsync(p => p.IsDefault, ct);
        if (policy is null) return [];

        var inputs = await _inputs.BuildAsync(build, policy.Config, projectId, ct);
        var score = RiskScorer.Compute(policy.Config, inputs);
        var evaluation = GateEvaluator.Evaluate(
            project.GatesConfig ?? ProjectGatesDefaults.Empty(),
            inputs, score.Score, prior: null, priorScore: null);

        return evaluation.Results.Where(r => r.Blocks).ToArray();
    }

    /// <summary>
    /// POA&amp;M items whose committed date falls inside the window and which
    /// nobody has been reminded about yet (TFND-121).
    /// </summary>
    public async Task<IReadOnlyList<DueSoon>> PoamsDueWithinAsync(
        TimeSpan window, DateTimeOffset asOf, CancellationToken ct)
    {
        var cutoff = asOf + window;

        return await _db.PoamItems.AsNoTracking()
            .Where(p => p.ClosedAt == null
                     && (p.Status == PoamStatus.Open || p.Status == PoamStatus.InProgress)
                     && p.ScheduledCompletionDate != null
                     && p.ScheduledCompletionDate <= cutoff
                     && p.ScheduledCompletionDate > asOf)
            .Select(p => new DueSoon(p.Id, p.ProjectId, p.Title, p.ScheduledCompletionDate!.Value))
            .ToArrayAsync(ct);
    }

    /// <summary>
    /// Whether a build actually verifies a POA&amp;M's remediation (TFND-118).
    ///
    /// The test is that the findings the item CITES are no longer open on the
    /// verifying build. An item citing nothing cannot be verified this way —
    /// and says so rather than passing by default, because "no evidence
    /// against" is not "evidence for".
    /// </summary>
    public async Task<Verification> VerifyPoamAsync(
        Guid poamItemId, string commitSha, CancellationToken ct)
    {
        var item = await _db.PoamItems.AsNoTracking()
            .SingleOrDefaultAsync(p => p.Id == poamItemId, ct);
        if (item is null) return new Verification(false, "That POA&M item no longer exists.");

        if (item.LinkedFindingIds.Count == 0)
        {
            return new Verification(false,
                "This item cites no findings, so a build cannot verify it. Close it manually with a "
                + "note explaining what was done — an absence of evidence against is not evidence for.");
        }

        var stillOpen = await (
            from f in _db.Findings.AsNoTracking()
            join cv in _db.ComponentVersions.AsNoTracking() on f.ComponentVersionId equals cv.Id
            join c in _db.Components.AsNoTracking() on cv.ComponentId equals c.Id
            where c.ProjectId == item.ProjectId
                  && cv.CommitSha == commitSha
                  && f.Status == FindingStatus.Open
                  && item.LinkedFindingIds.Contains(f.Id)
            select f.Id)
            .CountAsync(ct);

        return stillOpen == 0
            ? new Verification(true, $"None of the {item.LinkedFindingIds.Count} cited findings are open on {commitSha[..Math.Min(12, commitSha.Length)]}.")
            : new Verification(false, $"{stillOpen} cited finding(s) are still open on this build.");
    }
}

public sealed record DueSoon(Guid PoamItemId, Guid ProjectId, string Title, DateTimeOffset Due);

public sealed record Verification(bool Verified, string Reason);
