namespace Tamp.Findings.Domain.Entities;

// A frozen attestation (TFND-103).
//
// ADR 0001 is explicit about why this exists: "Workflow rules feeding scoring
// or gating must either be restricted to pure activities, or the attestation
// snapshot must store the verdict rather than expect to recompute it. A rule
// that calls an external API cannot be re-evaluated later to prove the
// attestation was sound." The snapshot is the honest half of that choice.
//
// The determinism requirement it satisfies: "an attestation signed in March
// must be reproducible in September, or the signature attests to nothing."
// Recomputing would not satisfy it — the policy may have been edited, an
// advisory feed may have moved, a suppression may have been written. All of
// those change the answer WITHOUT changing what was true when someone signed.
//
// Immutable once written, enforced in FindingsDbContext.SaveChanges the same
// way the audit trail is. A snapshot that can be edited is not evidence.
public sealed class AttestationSnapshot
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public Guid ProjectId { get; set; }

    // The build attested. An attestation is ABOUT a commit; "the latest build"
    // is a convenience for the screen and is never what gets signed.
    public required string CommitSha { get; set; }

    // The whole SsdfAttestationDoc as it was generated, verbatim. Stored as a
    // document rather than shredded into columns on purpose: the point is to
    // reproduce EXACTLY what the signatory saw, and a normalised schema would
    // have to be migrated as the document evolves — at which point old
    // snapshots start rendering differently than they did.
    public required string DocumentJson { get; set; }

    // Denormalised for listing and for the "changing the policy afterwards does
    // not alter a previously generated attestation" check, which has to be
    // answerable without deserialising every snapshot.
    public Guid? RiskPolicyId { get; set; }
    public required string RiskPolicyName { get; set; }
    public double Score { get; set; }
    public required string Band { get; set; }

    public Guid GeneratedByUserId { get; set; }
    public DateTimeOffset GeneratedAt { get; set; } = DateTimeOffset.UtcNow;

    // Set when a signatory records their sign-off. Null means generated but
    // unsigned — a distinction that matters, because an unsigned snapshot is a
    // record of what was true and a signed one is someone's claim about it.
    public DateTimeOffset? SignedAt { get; set; }
    public string? SignedBy { get; set; }
}
