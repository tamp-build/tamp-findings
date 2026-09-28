namespace Tamp.Findings.Domain.Entities;

// The versioned operational + supply-chain mandate definitions (TFND-188 / ADR 0010
// §7). Admin/policy-defined like the policy templates and the offering registry, because
// EOs/memos change. One IsCurrent pack; its Version is stamped onto every mandate result
// and POA&M for point-in-time defence. Crosswalked from EO directives (ADR 0011 §5).
public sealed class MandatePack
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public required string Version { get; set; }
    public bool IsCurrent { get; set; }
    public bool IsSeeded { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public List<MandateDefinition> Mandates { get; set; } = [];
}

public sealed class MandateDefinition
{
    public required string MandateId { get; set; }     // "encrypt-at-rest"
    public required string Title { get; set; }
    // Which analyzer produces the result (ADR 0010 §7): supply-chain → Findings,
    // operational → Ztt. Reuses MandateTool (defined with DirectiveCrosswalk).
    public MandateTool Tool { get; set; }
    // Drives the "where applicable" N/A (e.g. "has-network-surface" → IPv6 N/A when absent).
    public string? ApplicabilityRule { get; set; }
    // The conformance rule / gate key that proves it (the crosswalk target ref).
    public string? DerivationRuleRef { get; set; }
    // POA&M severity → the shared severity→window table on a fail.
    public Values.Severity PoamSeverity { get; set; }
    // Crosswalk back to the EO directive that mandates it (ADR 0011).
    public string? SourceDirectiveRef { get; set; }
}
