using Elsa.Extensions;
using Elsa.Scheduling.Activities;
using Elsa.Workflows;
using Elsa.Workflows.Activities;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Workflows.Definitions;

/// <summary>
/// The approval workflows (TFND-117, 119, 120, 123, 124).
///
/// A design note worth stating plainly, because the obvious implementation is
/// the wrong one:
///
/// THE APPROVAL ITSELF IS NOT ORCHESTRATED BY THE ENGINE. A
/// <see cref="PendingApproval"/> row is the state machine, and
/// <c>ApprovalService</c> enforces its transitions — one decision, by someone
/// who holds the capability, who is not the requester. That has to keep working
/// with the workflow engine stopped: a pending decision that vanishes when a
/// worker is down is worse than having no workflow at all, and a poll loop
/// waiting on a row it does not own would add an engine dependency to something
/// the database already answers correctly.
///
/// What the engine genuinely adds is TIME. A request that sits forever holds
/// its subject in a pending state, which DISABLES the actions that would race
/// it — a POA&amp;M nobody can act on because of a decision nobody will take is
/// a worse outcome than an un-approved one. So each workflow here is a timer
/// that expires an unanswered request, and nothing else.
///
/// These are DISPATCHED (persisted, background, waiting days). The rules path
/// is the opposite — in-process, synchronous, no persistence — and the two must
/// not be confused: a rule that blocked for a human would stall an ingest.
/// </summary>
public abstract class ApprovalWorkflowBase : WorkflowBase
{
    /// <summary>Which decision this workflow watches.</summary>
    protected abstract ApprovalKind Kind { get; }

    /// <summary>
    /// How long an unanswered request may hold its subject pending.
    /// </summary>
    protected abstract TimeSpan Expiry { get; }

    protected override void Build(IWorkflowBuilder builder)
    {
        var approvalId = builder.WithVariable<Guid>();

        builder.Root = new Sequence
        {
            Activities =
            {
                new Inline(async context =>
                {
                    // The row already exists — the application service that
                    // started this run created it — so the pending state is on
                    // screen from the instant of the request rather than
                    // whenever the engine gets to it.
                    var raw = context.WorkflowExecutionContext.Input.TryGetValue(ApprovalInput, out var value)
                        ? value?.ToString()
                        : null;

                    if (!Guid.TryParse(raw, out var id)) return;

                    approvalId.Set(context, id);

                    var bridge = context.GetRequiredService<WorkflowBridge>();
                    await bridge.LinkAsync(id, context.WorkflowExecutionContext.Id, context.CancellationToken);
                }),

                new Delay(Expiry),

                new Inline(async context =>
                {
                    var id = approvalId.Get<Guid>(context);
                    if (id == Guid.Empty) return;

                    var bridge = context.GetRequiredService<WorkflowBridge>();
                    var state = await bridge.StateOfAsync(id, context.CancellationToken);

                    // Decided, or gone. Either way there is nothing to expire,
                    // and the DECISION was already audited under the name of
                    // the person who took it.
                    if (state is null or not ApprovalState.Pending) return;

                    await bridge.ExpireAsync(id, context.CancellationToken);

                    await bridge.NoteAsync(
                        "approval.expired", AuditClass.Risk, ScopeTarget.Instance,
                        subjectId: id, subjectKind: nameof(PendingApproval),
                        detail: $"{Kind} went unanswered for {Describe(Expiry)} and was withdrawn, "
                              + "releasing the subject from its pending state",
                        context.CancellationToken);
                }),
            },
        };
    }

    private static string Describe(TimeSpan span) =>
        span.TotalDays >= 1 ? $"{span.TotalDays:0} days" : $"{span.TotalHours:0} hours";

    /// <summary>The input key every approval workflow reads its approval id from.</summary>
    public const string ApprovalInput = "approvalId";
}

/// <summary>
/// TFND-117. A POA&amp;M moving to Risk accepted.
///
/// The one approval that genuinely cannot be self-served: AcceptRisk is an
/// Authorizing Official decision that Admin deliberately does not hold, so
/// there is a second person in the loop by construction rather than by policy.
/// </summary>
public sealed class PoamRiskAcceptanceWorkflow : ApprovalWorkflowBase
{
    protected override ApprovalKind Kind => ApprovalKind.PoamRiskAcceptance;
    protected override TimeSpan Expiry => TimeSpan.FromDays(30);
}

/// <summary>
/// TFND-119. Moving a POA&amp;M's committed date.
///
/// Shorter expiry than the others on purpose: an extension request is about a
/// date that is approaching, and one that expires after the date has passed has
/// answered nothing.
/// </summary>
public sealed class PoamExtensionWorkflow : ApprovalWorkflowBase
{
    protected override ApprovalKind Kind => ApprovalKind.PoamExtension;
    protected override TimeSpan Expiry => TimeSpan.FromDays(14);
}

/// <summary>
/// TFND-120. A VEX statement moving from draft to published.
///
/// Lead Dev drafts, InfoSec publishes. The capability split already enforces
/// that; this makes the wait between them visible rather than leaving a draft
/// in a list nobody is looking at.
/// </summary>
public sealed class VexPublicationWorkflow : ApprovalWorkflowBase
{
    protected override ApprovalKind Kind => ApprovalKind.VexPublication;
    protected override TimeSpan Expiry => TimeSpan.FromDays(30);
}

/// <summary>
/// TFND-123. The signature on a frozen attestation snapshot.
///
/// The snapshot is immutable before this starts (TFND-103), so the thing being
/// signed cannot change while the signatory considers it — which is the whole
/// reason the freeze exists.
/// </summary>
public sealed class AttestationSignOffWorkflow : ApprovalWorkflowBase
{
    protected override ApprovalKind Kind => ApprovalKind.AttestationSignOff;
    // A signature is a scheduling problem, not a triage one. Two months is not
    // generous; it is realistic for getting a named officer's attention.
    protected override TimeSpan Expiry => TimeSpan.FromDays(60);
}

/// <summary>
/// TFND-124. Recycling an ingest key.
///
/// The approval IS the grace period. Recycling breaks every pipeline still
/// presenting the old key, so the gap between asking and doing is when someone
/// redeploys them — the delay is the feature rather than a cost of it.
/// </summary>
public sealed class IngestKeyRecycleWorkflow : ApprovalWorkflowBase
{
    protected override ApprovalKind Kind => ApprovalKind.IngestKeyRecycle;
    // Short: a key recycle is usually urgent, and a week-long wait would push
    // people to do it out of band.
    protected override TimeSpan Expiry => TimeSpan.FromDays(3);
}
