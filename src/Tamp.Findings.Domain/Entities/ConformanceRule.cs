using Tamp.Findings.Domain.Compliance;

namespace Tamp.Findings.Domain.Entities;

// The authoritative per-project conformance rule (TFND-190 / ADR 0012). tamp.findings is
// the store the analyzer fetches from and the generation step pushes to; the governed
// repo's adr-rules.json is the generation SOURCE, this is the served copy. Never
// hard-deleted — a past verdict cites the RulesSha it ran against, so a retired rule stays
// to explain history (RetiredAt stamped when a later generation drops it).
public sealed class ConformanceRule
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid ProjectId { get; set; }

    public required string AdrRef { get; set; }   // "ADR 0002"
    public required string RuleId { get; set; }   // "auth-boundary-single"; unique per (ProjectId, AdrRef, RuleId)

    // The ADR quote/claim the rule enforces.
    public string? Intent { get; set; }

    // How the rule is checked, and the check definition itself (a predicate, a pattern, or
    // a semantic prompt). CheckSpec is OPAQUE to findings — stored and served verbatim,
    // never interpreted here (the analyzer runs it).
    public ConformanceMethod Method { get; set; }
    public string? CheckSpec { get; set; }

    // The mapping the verdict also carries (ADR 0010 §6), emitted at generation time.
    public List<string> ControlRefs { get; set; } = [];
    public string? ZtPillar { get; set; }
    public string? ZtFunction { get; set; }
    public int? ZtStage { get; set; }
    public string? MandateId { get; set; }

    // Provenance. RulesSha is what a frozen verdict cites (ADR 0006), so a result can be
    // tied back to the exact rule it ran against.
    public string? RulesSha { get; set; }
    public string? ExtractionModelId { get; set; }

    // The review gate, now in findings (ADR 0012 §4). Draft may run and report; policy
    // decides whether an unreviewed rule can block.
    public ReviewStatus ReviewStatus { get; set; } = ReviewStatus.Draft;

    public DateTimeOffset PushedAt { get; set; } = DateTimeOffset.UtcNow;
    // Soft-retire: set when a later generation no longer contains this rule. Active rules
    // (the served set) are those with RetiredAt == null.
    public DateTimeOffset? RetiredAt { get; set; }
}
