using System.Text;
using System.Text.RegularExpressions;

namespace Tamp.Findings.Web.Localization;

/// <summary>
/// Pseudo-localisation: a synthetic locale that makes i18n defects visible
/// before any real translation exists.
///
/// Ported from the React implementation this replaces (web/src/i18n/pseudo.ts),
/// which retires with the SPA under TFND-128. It does three jobs at once, and
/// each catches a class of bug an English-only build cannot:
///
///   1. Accents every letter. Anything still rendering as plain ASCII is a
///      hardcoded string that never went through the catalogue.
///   2. Pads by ~40%. German and Finnish routinely run that much longer than
///      English; padding surfaces truncation and overflow now rather than
///      after a translator has been paid.
///   3. Brackets the whole string. A missing bracket means the text was cut
///      off, and interpolated values stay readable inside.
///
/// The hand-off is explicit that this matters here more than usual: several
/// layouts are CSS grids with fixed columns, and "those columns are minimums
/// chosen for English and must be verified against a pseudo-locale". The score
/// contribution table — 150px minmax(120px,1fr) 74px 34px minmax(160px,1.15fr)
/// — is the design's own worst case.
/// </summary>
public static class PseudoLocale
{
    /// <summary>
    /// The culture that triggers pseudo-localisation. "qps-ploc" is the
    /// Windows/.NET convention for a pseudo-locale, so tooling and browsers
    /// already treat it as a real, non-neutral culture.
    /// </summary>
    public const string CultureName = "qps-ploc";

    // Placeholders must survive untouched — mangling them would break the very
    // substitution being tested. Covers {0}, {name}, {0:F1} and the composed
    // fragments the hand-off requires instead of embedded markup.
    private static readonly Regex Preserve = new(@"(\{[^{}]*\})", RegexOptions.Compiled);

    private static readonly Dictionary<char, string> Map = new()
    {
        ['a'] = "á", ['b'] = "ƀ", ['c'] = "ç", ['d'] = "ð", ['e'] = "é", ['f'] = "ƒ",
        ['g'] = "ĝ", ['h'] = "ĥ", ['i'] = "í", ['j'] = "ĵ", ['k'] = "ķ", ['l'] = "ł",
        ['m'] = "ɱ", ['n'] = "ñ", ['o'] = "ó", ['p'] = "þ", ['q'] = "q", ['r'] = "ŕ",
        ['s'] = "ş", ['t'] = "ţ", ['u'] = "ú", ['v'] = "ṽ", ['w'] = "ŵ", ['x'] = "ẋ",
        ['y'] = "ý", ['z'] = "ž",
        ['A'] = "Á", ['B'] = "Ɓ", ['C'] = "Ç", ['D'] = "Ð", ['E'] = "É", ['F'] = "Ƒ",
        ['G'] = "Ĝ", ['H'] = "Ĥ", ['I'] = "Í", ['J'] = "Ĵ", ['K'] = "Ķ", ['L'] = "Ł",
        ['M'] = "Ṁ", ['N'] = "Ñ", ['O'] = "Ó", ['P'] = "Þ", ['Q'] = "Q", ['R'] = "Ŕ",
        ['S'] = "Ş", ['T'] = "Ţ", ['U'] = "Ú", ['V'] = "Ṽ", ['W'] = "Ŵ", ['X'] = "Ẋ",
        ['Y'] = "Ý", ['Z'] = "Ž",
    };

    // Padding is appended as visible glyphs rather than spaces so it cannot be
    // collapsed by white-space handling — the point is to occupy width.
    private const string Padding = "·˙·˙·˙·˙·˙·˙·˙·˙·˙·˙·˙·˙·˙·˙·˙·˙·˙·˙·˙·˙";

    /// <summary>Expansion factor. ~40%, per the hand-off's design guidance.</summary>
    public const double ExpansionFactor = 0.4;

    public static string Transform(string? value)
    {
        if (string.IsNullOrEmpty(value)) return value ?? string.Empty;

        var sb = new StringBuilder(value.Length * 2);
        sb.Append('⟦');

        var accentedLength = 0;
        foreach (var part in Preserve.Split(value))
        {
            if (part.Length == 0) continue;

            // A preserved placeholder passes through verbatim and does not
            // count toward the length being padded — it will be replaced by a
            // real value whose width we cannot know here.
            if (Preserve.IsMatch(part) && part.StartsWith('{'))
            {
                sb.Append(part);
                continue;
            }

            foreach (var ch in part)
            {
                sb.Append(Map.TryGetValue(ch, out var mapped) ? mapped : ch.ToString());
                if (!char.IsWhiteSpace(ch)) accentedLength++;
            }
        }

        var padLength = (int)Math.Ceiling(accentedLength * ExpansionFactor);
        if (padLength > 0)
        {
            sb.Append(' ');
            sb.Append(Padding.AsSpan(0, Math.Min(padLength, Padding.Length)));
        }

        sb.Append('⟧');
        return sb.ToString();
    }
}
