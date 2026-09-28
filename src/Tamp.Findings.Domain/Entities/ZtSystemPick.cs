namespace Tamp.Findings.Domain.Entities;

// An owner's per-function pick (TFND-188 / ADR 0010 §4, brief §5). NotApplicable is a
// role declaration ("this system does no auth; it is headless") that removes the
// function from the denominator entirely — the correct home for what a naive
// questionnaire encodes as a bogus "option 5 = headless" top-of-scale option. It must
// NEVER be collapsed into a stage-1 (the scale-poisoning guard). Committed records an
// owner's asserted intent pending evidence.
public sealed class ZtSystemPick
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid SystemId { get; set; }
    public required string Pillar { get; set; }
    public required string Function { get; set; }

    public ZtPickKind Kind { get; set; }
    // Required for NotApplicable — the role declaration justifying removal from scope.
    public string? Justification { get; set; }

    public Guid AuthorUserId { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}

public enum ZtPickKind { NotApplicable = 0, Committed = 1 }
