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
// The row is what makes a pending state visible: a POA&M, VEX statement or
// attestation carries no "awaiting approval" flag of its own, so this row is the
// single place the screens read to know a decision is outstanding.
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

    // Kind-specific data the EFFECT needs that the decision itself does not —
    // e.g. the proposed new date for a POA&M extension (TFND-119). Opaque JSON
    // to ApprovalService; each IApprovalEffect owns its own shape and parses it.
    // Null for kinds whose effect needs nothing beyond the subject (a risk
    // acceptance, a completion).
    public string? Payload { get; set; }
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
    // Loosening a policy template lowers the floor for every client and project
    // under it (ADR 0007) — an InfoSec risk decision, not a policy edit.
    LoosenPolicyTemplate = 6,
    // Switching a client's template swaps its whole inherited baseline (ADR 0007).
    SwitchClientTemplate = 7,
    // An SBOM-staleness exemption stops a component counting against the score
    // (TFND-225). Distinct from VexPublication although the artifact is a VEX
    // statement and the capability is the same one: publication has a direct path
    // for whoever holds PublishVex, and this deliberately has none — a
    // score-lowering override with no second person is the first thing an auditor
    // questions, so every exemption goes through a request, including an InfoSec
    // officer's own.
    StalenessExemption = 8,
    // A project disposition that WEAKENS a stricter template/archetype default
    // (ADR 0015 §5, TFND-219). AcceptRisk, like the other two loosenings: the
    // control stops being proven on this project, and that is a risk decision, not
    // a policy edit — which is why Admin deliberately does not hold it even though
    // Admin is who authors dispositions.
    ControlDispositionDowngrade = 9,
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
