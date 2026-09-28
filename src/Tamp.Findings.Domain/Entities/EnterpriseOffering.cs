namespace Tamp.Findings.Domain.Entities;

// A provider node (TFND-188 / ADR 0010 §2, §5): an admin-defined, free-form enterprise
// offering that CONFERS per-function ZT stage scores to the systems that inherit it.
// The engine ships no built-in catalog and encodes nothing about any specific
// technology — the admin names a service-level id and declares the per-function scores,
// and that is the whole definition. Distinct tiers of one tool are distinct offerings.
// Scored ONCE and inherited by N systems; min-cap flows downhill (ADR 0010 §5). Always
// client-scoped.
public sealed class EnterpriseOffering
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid ClientId { get; set; }

    // The admin's free-form id, e.g. "splunk-premium". Unique within a client.
    public required string ServiceLevelId { get; set; }
    public required string Name { get; set; }
    public string? Description { get; set; }

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    // Per-function stage scores this offering confers, inline as jsonb.
    public List<OfferingFunctionScore> FunctionScores { get; set; } = [];
}

public sealed class OfferingFunctionScore
{
    public required string Pillar { get; set; }
    public required string Function { get; set; }
    // 1-4 — the cap that flows downhill to every consumer inheriting this function.
    public int Stage { get; set; }
}
