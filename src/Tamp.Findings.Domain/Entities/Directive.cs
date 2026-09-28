namespace Tamp.Findings.Domain.Entities;

// One obligation extracted from an instrument (ADR 0011 §2, §3). Aspirational
// language ("shall promote", "encourage") is dropped at extraction by abstention and
// never stored — only self-executing dated requirements and delegations become rows.
public sealed class Directive
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public Guid InstrumentId { get; set; }
    public string? Section { get; set; }

    // A stable, human-readable reference for crosswalks and amendment-diffs, e.g.
    // "EO14144§4(e)". Unique — an amending instrument names the directives it rescinds
    // by this ref.
    public required string Ref { get; set; }

    public required string Who { get; set; }        // agency / role responsible
    public required string MustDo { get; set; }     // the requirement

    public DirectiveType Type { get; set; }
    public DirectiveApplicability Applicability { get; set; }

    // Date anchoring (ADR 0011 §4). Absolute is taken as-is; Relative needs an anchor
    // (the signing date, or a predicate memo's issue date) + an offset; Pending is a
    // first-class state for a directive whose anchor event has not occurred yet.
    public ByWhenKind ByWhenKind { get; set; }
    public DateTimeOffset? AbsoluteDate { get; set; }
    public int? RelativeOffsetDays { get; set; }
    public AnchorKind? AnchorKind { get; set; }
    public Guid? AnchorInstrumentId { get; set; }
    // Filled once the anchor lands and the offset resolves; null while Pending.
    public DateTimeOffset? ResolvedDate { get; set; }

    // Provenance stamp (mirrors the instrument's).
    public string? SourceHash { get; set; }
    public string? ExtractionModelId { get; set; }
    public ReviewStatus ReviewStatus { get; set; } = ReviewStatus.Draft;

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}

// Only SelfExecutingDated becomes a technical check (crosswalks to findings/ztt).
// Delegation is a tracking milestone + forward link to the memo that will carry the
// real deadline; it is not a check. (Aspirational is dropped, never stored.)
public enum DirectiveType { SelfExecutingDated = 0, Delegation = 1 }

public enum DirectiveApplicability { AllSystems = 0, NationalSecuritySystems = 1, WhereApplicable = 2 }

public enum ByWhenKind { Absolute = 0, Relative = 1, Pending = 2 }

public enum AnchorKind { SigningDate = 0, PredicateMemoIssue = 1 }
