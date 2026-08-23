using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Domain.Entities;

// A decision waiting on a person (TFND-116).
//
// One representation used by POA&M, VEX and attestation alike, because the
// hand-off's requirement is a GRAMMAR rather than three features: "a POA&M
// awaiting risk-acceptance approval is neither Open nor Risk accepted". Three
// separate pending flags would have produced three slightly different answers
// to the same question.
//
// The row is what makes a pending state visible without asking the workflow
// engine. Elsa owns the orchestration; this owns what the screens read, and the
// two are linked by WorkflowInstanceId so an operator can find one from the
// other.
public sealed class PendingApproval
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public ApprovalKind Kind { get; set; }

    // What is being decided. SubjectKind is the entity name so a row can be
    // resolved without a discriminator column per type.
    public required string SubjectKind { get; set; }
    public Guid SubjectId { get; set; }

    // Scope, for the audit entry and for the capability check when the
    // decision is taken. Denormalised rather than walked from the subject:
    // the subject may be deleted before the decision is made, and a pending
    // approval that cannot say what it was about is worthless.
    public Guid? ClientId { get; set; }
    public Guid? ProjectId { get; set; }

    public Guid RequestedByUserId { get; set; }
    public required string RequestedByLogin { get; set; }
    public DateTimeOffset RequestedAt { get; set; } = DateTimeOffset.UtcNow;

    // Free text from the requester — why they are asking. Surfaces to whoever
    // decides, because "approve this" with no reason is not a decision anybody
    // can make well.
    public string? Justification { get; set; }

    // Who this is waiting on.
    //
    // A specific user when one was named; otherwise null, meaning "anyone
    // holding the capability at this scope". The "Awaiting you" filter is
    // driven by BOTH — the hand-off asks for real assignment rather than role
    // alone, and a null assignee still resolves to real people through the
    // capability, not to everybody.
    public Guid? AssignedToUserId { get; set; }

    public ApprovalState State { get; set; } = ApprovalState.Pending;

    public Guid? DecidedByUserId { get; set; }
    public string? DecidedByLogin { get; set; }
    public DateTimeOffset? DecidedAt { get; set; }
    public string? DecisionNote { get; set; }

    // The Elsa instance orchestrating this, when one is running. Null for an
    // approval created outside a workflow — the product works with the engine
    // switched off, and a pending decision must not depend on it.
    public string? WorkflowInstanceId { get; set; }
}

// What is being decided. The kind drives which capability the decider needs,
// so adding one means deciding who may take it.
public enum ApprovalKind
{
    // InfoSec only — an Authorizing Official decision that Admin deliberately
    // does not hold.
    PoamRiskAcceptance = 0,
    // Needs a verifying build (TFND-118).
    PoamCompletion = 1,
    // Moving a committed date, with the AO's reason on the record.
    PoamExtension = 2,
    // Lead Dev drafts, InfoSec publishes.
    VexPublication = 3,
    // The signature on a frozen attestation snapshot.
    AttestationSignOff = 4,
    // Recycling an ingest key breaks CI until pipelines redeploy.
    IngestKeyRecycle = 5,
}

public enum ApprovalState
{
    Pending = 0,
    Approved = 1,
    Rejected = 2,
    // The thing being decided went away, or the requester withdrew. Not a
    // rejection: nobody said no.
    Cancelled = 3,
}
