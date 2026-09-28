namespace Tamp.Findings.Domain.Entities;

// The authority graph (ADR 0011 §2) — the heart of the registry. An EO rarely
// stands alone: it amends prior EOs, delegates to memos, and the memos implement the
// EO. A typed, directed edge from one instrument (optionally a specific section) to
// another. Modeled as first-class edges, not flat foreign keys, so the graph is
// walkable in either direction ("what does EO 14306 amend, and what did that kill").
public sealed class InstrumentRelation
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public Guid FromInstrumentId { get; set; }
    public Guid ToInstrumentId { get; set; }
    public InstrumentRelationType Type { get; set; }

    // Optional section anchors, e.g. From "§4(e)" of the amending order to a section
    // of the amended one.
    public string? FromSection { get; set; }
    public string? ToSection { get; set; }
}

public enum InstrumentRelationType { Amends = 0, Revokes = 1, Supersedes = 2, Implements = 3 }
