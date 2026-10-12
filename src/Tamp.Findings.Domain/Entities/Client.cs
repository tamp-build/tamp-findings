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

    // LEGACY, and never read since TFND-247. Superseded by PolicyLayer.Mode
    // below, which is what the client policy screen writes and what the merge
    // resolves strictest-wins.
    //
    // Kept as a column rather than dropped: it is null on every row in every
    // instance we can see (nothing has written it since the layers landed), so
    // a migration would be churn for no behaviour — but removing the property
    // would be a schema change in a release whose point is that enforcement
    // resolution stopped being ambiguous. Drop it in a cleanup of its own.
    [Obsolete("Set PolicyLayer.Mode instead; nothing reads this (TFND-247).")]
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
