namespace Tamp.Findings.Domain.Entities;

// tamp-EOProvenance (ADR 0011). An executive order, OMB memo, NSM, or presidential
// memo — the political-layer instrument that carries (or delegates) mandates. The
// registry tracks EOs and their implementing memos only; NIST/technical reference
// stays in the control/maturity catalogs.
public sealed class Instrument
{
    public Guid Id { get; set; } = Guid.NewGuid();

    // "EO 14028", "M-22-09". Unique.
    public required string Identifier { get; set; }
    public required string Title { get; set; }
    public InstrumentType Type { get; set; }

    public string? IssuingAuthority { get; set; }

    // The signing / issue date. The default anchor for a directive's relative
    // "within N days of the order" deadline (ADR 0011 §4).
    public DateTimeOffset IssueDate { get; set; }

    // Federal Register or publication cite.
    public string? PublicationCite { get; set; }

    // Provenance (ADR 0006 discipline): hash of the canonical source text, the
    // model that extracted the directives, and whether a human has reviewed the
    // extraction. Source-hash drift without a regenerated corpus fails closed —
    // the instrument stays Draft and its directives never go Active.
    public string? SourceHash { get; set; }
    public string? ExtractionModelId { get; set; }
    public ReviewStatus ReviewStatus { get; set; } = ReviewStatus.Draft;

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}

public enum InstrumentType { ExecutiveOrder = 0, OmbMemo = 1, Nsm = 2, PresidentialMemo = 3 }

// A model-assisted extraction is trusted only after human review — the stakes here
// are legal/political (ADR 0011 §6). Draft directives never enter the in-force set.
public enum ReviewStatus { Draft = 0, Reviewed = 1 }
