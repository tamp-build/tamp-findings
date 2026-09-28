using System.Text.Json.Serialization;

namespace Tamp.Findings.Domain.Compliance;

/// <summary>
/// Which FedRAMP / 800-53B baselines a control belongs to. A flags enum because
/// a control is commonly in several (Low ⊂ Moderate ⊂ High is the usual shape,
/// but not guaranteed — the membership comes from the imported profile, not an
/// assumption).
/// </summary>
[Flags]
public enum BaselineLevel
{
    None = 0,
    Low = 1,
    Moderate = 2,
    High = 4,
}

/// <summary>The two kinds of organization-defined parameter in an 800-53
/// statement: an <c>[Assignment: …]</c> value, or a <c>[Selection …]</c> choice.</summary>
public enum ParameterKind
{
    Assignment,
    Selection,
}

/// <summary>One piece of a parsed statement line: either literal prose, or an
/// organization-defined parameter to render as a chip.</summary>
public sealed record StatementSegment(bool IsParameter, string Text, ParameterKind? Kind);

/// <summary>
/// One control from a catalog (e.g. NIST SP 800-53 Rev 5). The statement is kept
/// as the catalog's lines, with organization-defined parameters left inline; the
/// <see cref="ControlStatementParser"/> turns each line into text + parameter
/// segments for display. Baseline membership drives the Low/Moderate/High chips.
/// </summary>
public sealed class Control
{
    public required string Id { get; set; }          // "CM-6"
    public required string Title { get; set; }        // "Configuration Settings"
    public required string Family { get; set; }       // "Configuration Management"
    public BaselineLevel Baselines { get; set; }
    public List<string> StatementLines { get; set; } = [];

    /// <summary>Whether this control is in a given baseline.</summary>
    public bool InBaseline(BaselineLevel level) => (Baselines & level) == level && level != BaselineLevel.None;

    /// <summary>The organization-defined parameters across the whole statement.
    /// Computed — not persisted (this class is stored as jsonb).</summary>
    [JsonIgnore]
    public IReadOnlyList<StatementSegment> Parameters =>
        StatementLines.SelectMany(ControlStatementParser.Parse).Where(s => s.IsParameter).ToArray();
}
