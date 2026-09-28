namespace Tamp.Findings.Domain.Entities;

/// <summary>How a framework was built (v3 §6). Drives the provenance badge.</summary>
public enum FrameworkKind
{
    /// <summary>Imported from an OSCAL baseline profile — the recommended path.</summary>
    Oscal,
    /// <summary>Curated by hand from a control list with no OSCAL source (e.g. GovRAMP).</summary>
    Curated,
    /// <summary>Tailors another framework — adds controls or overrides parameters.</summary>
    Overlay,
}

public enum FrameworkStatus
{
    Current,
    Draft,
}

/// <summary>
/// A compliance framework a client's projects are held to (v3 §6): a FedRAMP
/// baseline, a curated list like GovRAMP, or an overlay that tailors one. A
/// framework selects controls FROM the catalog — its control count and baseline
/// membership are computed from the imported profile, never hard-coded, so this
/// row carries provenance and a display label rather than a derived truth it
/// could drift from.
/// </summary>
public sealed class Framework
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public required string Slug { get; set; }         // "fr-mod"
    public required string Name { get; set; }         // "FedRAMP Rev 5 Moderate"
    public FrameworkKind Kind { get; set; }
    public required string Source { get; set; }       // provenance prose
    public required string Version { get; set; }      // "Rev 5 · 2026-05"

    /// <summary>What the frameworks table shows for the control count — a label,
    /// not a number, because a draft or overlay reads as "112 of ~" / "+6
    /// controls" until its profile is fully imported.</summary>
    public string? ControlCountLabel { get; set; }
    public string? ParamsLabel { get; set; }          // "FedRAMP-assigned values"
    public FrameworkStatus Status { get; set; }
    public bool IsSeeded { get; set; }
}
