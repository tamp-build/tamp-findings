namespace Tamp.Findings.Domain.Entities;

// A system inherits one pillar-function from an enterprise offering (TFND-188 / ADR
// 0010 §5). The edge is ATTESTED, not machine-verified: tamp-ztt records who attested,
// when, and what evidence they attached, and freezes it as audit-ready provenance — it
// does not judge whether the evidence proves reality (in a government audit the chain of
// custody is the deliverable, not a truth claim). A Statement is mandatory for
// edge-attested; a bare edge with no attestation is edge-committed (scored but flagged).
// Attestations go stale: ExpiresAt = AttestedAt + the client's cadence, after which
// edge-attested degrades back toward edge-committed until refreshed.
public sealed class ZtInheritanceEdge
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid SystemId { get; set; }
    public Guid OfferingId { get; set; }
    public required string Pillar { get; set; }
    public required string Function { get; set; }

    // Attestation (all null ⇒ edge-committed).
    public string? AttesterName { get; set; }
    public string? AttesterLogin { get; set; }
    public string? Statement { get; set; }        // mandatory for edge-attested
    public string? EvidenceRef { get; set; }       // uploaded artifact ref / URL / email id
    public DateTimeOffset? AttestedAt { get; set; }
    public DateTimeOffset? ExpiresAt { get; set; }  // per-client cadence; stale ⇒ degrades

    public Guid AuthorUserId { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}
