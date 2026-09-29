namespace Tamp.Findings.Domain.Entities;

/// <summary>
/// One undocumented-decision advisory for a build (ADR 0013): reverse-examination — an
/// architectural decision the code made that NO ADR records. It is the inverse of a
/// <see cref="ConformanceFinding"/> (which checks code AGAINST an ADR); this finds code with
/// no governing ADR at all, a CM-3 change-control drift signal.
///
/// ADVISORY, ALWAYS. It never gates a build, never carries a verdict, and never raises a
/// POA&amp;M — the remedy is "write an ADR." tamp.findings is the SINK: these rows are produced
/// by tamp-conformance's reverse-examination and ingested here as governance evidence, frozen
/// at the commit they were detected against.
/// </summary>
public sealed class DecisionDiagnostic
{
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>The build this decision was detected against.</summary>
    public Guid ComponentVersionId { get; set; }

    /// <summary>The full advisory rule id, "undocumented-decision:new-dependency".</summary>
    public required string RuleId { get; set; }

    /// <summary>The decision kind — the suffix of <see cref="RuleId"/> after the colon
    /// ("new-dependency", "new-endpoint", …). Drives grouping and the filter.</summary>
    public required string Kind { get; set; }

    /// <summary>The decision summary the model produced — what was decided that no ADR records.</summary>
    public required string Summary { get; set; }

    /// <summary>file:line the decision anchors to.</summary>
    public string? Location { get; set; }

    /// <summary>The commit this was detected against, frozen for point-in-time evidence.</summary>
    public string? CommitSha { get; set; }

    /// <summary>800-53 controls this advisory maps to. Undocumented decisions are inherently a
    /// CM-3 (change control) signal; the producer may narrow it further.</summary>
    public List<string> ControlRefs { get; set; } = ["CM-3"];

    public DateTimeOffset DetectedAt { get; set; } = DateTimeOffset.UtcNow;
}
