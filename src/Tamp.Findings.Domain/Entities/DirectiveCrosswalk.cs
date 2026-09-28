namespace Tamp.Findings.Domain.Entities;

// The join that turns a political directive into a per-system, as-of-date status
// (ADR 0011 §5): a surviving dated requirement links to the check that proves it in
// tamp-findings or tamp-ztt. The Target names the ANALYZER that produces the result,
// not the store — every result lives in tamp.findings regardless.
public sealed class DirectiveCrosswalk
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public Guid DirectiveId { get; set; }
    public MandateTool Target { get; set; }

    // The mandate id / gate key / conformance rule id the analyzer proves it with,
    // e.g. "encrypt-in-transit". Unique per Target so no mandate is double-scored.
    public required string TargetRef { get; set; }
}

// The analysis partition (ADR 0010 §7, ADR 0011 §5): supply-chain mandates are
// produced by tamp-findings from build evidence; operational mandates (encryption,
// MFA, IPv6) are produced by tamp-ztt. Shared by the crosswalk and the ztt mandate
// pack.
public enum MandateTool { Findings = 0, Ztt = 1 }
