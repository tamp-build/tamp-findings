using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Domain.Entities;

public sealed class Client
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public required string Name { get; set; }
    public string? Description { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    // Null → fall back to the system default policy. Set → applies to
    // every project under this client unless the project overrides.
    public Guid? RiskPolicyId { get; set; }

    // Null → inherit the instance enforcement mode. Set → applies to every
    // project under this client unless the project overrides (TFND-148).
    public EnforcementMode? EnforcementMode { get; set; }

    // The three-layer policy (ADR 0007 / TFND-179). The template this client
    // inherits its baseline from (null → none yet), and the client's own
    // hardening ON TOP of it. The client can only add or tighten; switching the
    // template needs InfoSec approval.
    public Guid? PolicyTemplateId { get; set; }
    public Risk.PolicyLayer? PolicyLayer { get; set; }

    // The compliance framework this client's projects are held to (TFND-177,
    // v3 §6). Null → none assigned. Projects inherit it.
    public Guid? FrameworkId { get; set; }

    // Zero Trust (TFND-188 / ADR 0010). ZTMM rides its OWN axis, separate from the
    // singular FrameworkId, because a client held to a control baseline is also
    // ZT-scored. Null → the client's systems are not ZT-scored.
    public Guid? MaturityModelId { get; set; }
    // Per-client attestation policy for inheritance edges (ADR 0010 §5): the cadence
    // after which an edge-attested inheritance goes stale, and what evidence an
    // attestation must carry (a statement is always mandatory). Null → a sensible
    // default applied by the resolver.
    public int? ZtAttestationExpiryDays { get; set; }
    public string? ZtAttestationRequirement { get; set; }

    public ICollection<Project> Projects { get; set; } = [];
}
