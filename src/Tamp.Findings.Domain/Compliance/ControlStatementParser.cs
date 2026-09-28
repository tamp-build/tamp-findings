namespace Tamp.Findings.Domain.Compliance;

/// <summary>
/// Parses an 800-53 control statement line into literal text and
/// organization-defined parameter segments (v3 §6). Pure and deterministic.
///
/// Parameters are the bracketed tokens the catalog leaves for an organization to
/// fill — <c>[Assignment: organization-defined frequency]</c> or
/// <c>[Selection (one or more): …]</c>. The parse counts bracket depth so a
/// NESTED parameter is one chip, not several: in
/// <c>[Selection (one or more): [Assignment: …]; when [Assignment: …]]</c> the
/// whole outer selection is a single segment, because the reader fills it as one
/// decision.
/// </summary>
public static class ControlStatementParser
{
    public static IReadOnlyList<StatementSegment> Parse(string line)
    {
        var segments = new List<StatementSegment>();
        if (string.IsNullOrEmpty(line)) return segments;

        int i = 0, textStart = 0;
        while (i < line.Length)
        {
            if (line[i] != '[') { i++; continue; }

            // Flush the literal text before this parameter.
            if (i > textStart)
                segments.Add(new StatementSegment(false, line[textStart..i], null));

            // Walk to the MATCHING close bracket, counting depth so nested
            // parameters stay inside this one segment.
            int depth = 0, j = i;
            for (; j < line.Length; j++)
            {
                if (line[j] == '[') depth++;
                else if (line[j] == ']' && --depth == 0) break;
            }

            // j is the matching ']' (or the end, for an unbalanced statement).
            int end = j < line.Length ? j + 1 : line.Length;
            var span = line[i..end];
            var kind = span.StartsWith("[Selection", StringComparison.Ordinal)
                ? ParameterKind.Selection
                : ParameterKind.Assignment;
            segments.Add(new StatementSegment(true, span, kind));

            i = end;
            textStart = end;
        }

        if (textStart < line.Length)
            segments.Add(new StatementSegment(false, line[textStart..], null));

        return segments;
    }

    /// <summary>Total organization-defined parameters across a control's lines —
    /// the count the frameworks table and the statement panel report.</summary>
    public static int CountParameters(IEnumerable<string> statementLines) =>
        statementLines.Sum(l => Parse(l).Count(s => s.IsParameter));

    /// <summary>Parse the catalog's compact baseline flag string ("LMH", "MH",
    /// "H", "L") into a <see cref="BaselineLevel"/>.</summary>
    public static BaselineLevel ParseBaselines(string? flags)
    {
        var level = BaselineLevel.None;
        if (string.IsNullOrEmpty(flags)) return level;
        if (flags.Contains('L')) level |= BaselineLevel.Low;
        if (flags.Contains('M')) level |= BaselineLevel.Moderate;
        if (flags.Contains('H')) level |= BaselineLevel.High;
        return level;
    }
}
