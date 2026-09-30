using System.Globalization;
using System.Text;
using Tamp.Findings.Domain.Risk;

namespace Tamp.Findings.Application.Projects;

/// <summary>
/// Renders a <see cref="ProjectStatus"/> as a self-contained status-card SVG — the public badge.
/// No stylesheet (an embedded README image has none): colours come from <see cref="BandExtensions.Hex"/>,
/// the same single source the app's CSS band tokens track, so the badge cannot drift from the header.
/// The build sha + timestamp are drawn on the card so a viewer can spot a stale (proxy-cached) copy.
/// </summary>
public static class BadgeSvg
{
    private const string CardBg = "#0f1420";
    private const string Border = "#2a3446";
    private const string Ink = "#e8edf5";
    private const string Muted = "#8a97ad";
    private const string Faint = "#6b7789";

    public static string Render(ProjectStatus s, DateTimeOffset generatedAt)
    {
        string Hex(string slug) => BandExtensions.FromSlug(slug).Hex();

        var subtitle = string.IsNullOrWhiteSpace(s.Baseline) ? s.ClientName : $"{s.ClientName} · {s.Baseline}";
        var shipValue = s.ClearToShip ? "✓ Clear" : "✕ Blocked";
        var shipHex = Hex(s.ShipBand);
        var (sub1, sub2) = ShipSub(s.ShipReasons);
        var build = s.CommitShaShort ?? "unknown";
        var built = s.BuiltAt.ToUniversalTime().ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture);

        var sb = new StringBuilder(2048);
        sb.Append("""<svg xmlns="http://www.w3.org/2000/svg" width="560" height="184" viewBox="0 0 560 184" role="img" font-family="'Segoe UI',system-ui,-apple-system,Roboto,Helvetica,Arial,sans-serif">""");
        sb.Append($"""<title>{Esc(s.ProjectName)} — {(s.ClearToShip ? "clear to ship" : "blocked")}</title>""");
        sb.Append("""<defs><clipPath id="c"><rect x="1" y="1" width="558" height="182" rx="12"/></clipPath></defs>""");
        sb.Append($"""<g clip-path="url(#c)"><rect width="560" height="184" fill="{CardBg}"/></g>""");
        sb.Append($"""<rect x="1" y="1" width="558" height="182" rx="12" fill="none" stroke="{Border}" stroke-width="1.5"/>""");

        // header
        sb.Append($"""<text x="24" y="36" fill="{Ink}" font-size="20" font-weight="700">{Esc(s.ProjectName)}</text>""");
        sb.Append($"""<text x="24" y="56" fill="{Muted}" font-size="12.5">{Esc(subtitle)}</text>""");

        // stat cells — the suffix (%, or " / total") renders smaller so wide values stay in the box.
        var inv = CultureInfo.InvariantCulture;
        Cell(sb, 24, 118, Hex(s.RiskBand), $"Risk · {s.RiskBand}", Num(s.RiskScore), "%", 26);
        if (s.CoverageMeasured) Cell(sb, 148, 118, Hex(s.CoverageBand), "Coverage", Num(s.CoveragePercent), "%", 26);
        else Cell(sb, 148, 118, Hex(s.CoverageBand), "Coverage", "no data", "", 20);
        if (s.TestsMeasured) Cell(sb, 272, 132, Hex(s.TestsBand), "Tests passing", s.TestsPassed.ToString("N0", inv), $" / {s.TestsTotal.ToString("N0", inv)}", 22);
        else Cell(sb, 272, 132, Hex(s.TestsBand), "Tests passing", "no data", "", 20);

        // ship cell (its own layout: verdict in band colour + up to two wrapped reason lines)
        sb.Append($"""<g transform="translate(410,74)">""");
        sb.Append($"""<rect width="126" height="82" rx="8" fill="{shipHex}" fill-opacity="0.12"/>""");
        sb.Append($"""<rect width="126" height="3" rx="1.5" fill="{shipHex}"/>""");
        sb.Append($"""<text x="12" y="26" fill="{Muted}" font-size="11" letter-spacing="0.3">Ship gate</text>""");
        sb.Append($"""<text x="12" y="50" fill="{shipHex}" font-size="19" font-weight="700">{Esc(shipValue)}</text>""");
        if (sub1 is not null) sb.Append($"""<text x="12" y="66" fill="#98a3b6" font-size="10">{Esc(sub1)}</text>""");
        if (sub2 is not null) sb.Append($"""<text x="12" y="78" fill="#98a3b6" font-size="10">{Esc(sub2)}</text>""");
        sb.Append("</g>");

        // build stamp (staleness) + powered-by
        sb.Append($"""<text x="24" y="176" font-size="10"><tspan fill="{Faint}">build </tspan><tspan fill="#98a3b6" font-weight="600" font-family="ui-monospace,'Cascadia Code',Consolas,monospace">{Esc(build)}</tspan><tspan fill="{Faint}"> · {Esc(built)} UTC</tspan></text>""");
        sb.Append($"""<text x="536" y="176" text-anchor="end" font-size="10"><tspan fill="{Faint}">powered by </tspan><tspan fill="#8fa0bd" font-weight="600">tamp-findings</tspan><tspan fill="{Faint}"> · github.com/tamp-build</tspan></text>""");
        sb.Append("</svg>");
        return sb.ToString();
    }

    /// <summary>A project with no ingested build yet — a badge that says so rather than a fake clean one.</summary>
    public static string RenderUnbuilt(string projectName, string? subtitle)
    {
        var sb = new StringBuilder(700);
        sb.Append("""<svg xmlns="http://www.w3.org/2000/svg" width="560" height="96" viewBox="0 0 560 96" role="img" font-family="'Segoe UI',system-ui,-apple-system,Roboto,Helvetica,Arial,sans-serif">""");
        sb.Append($"""<rect x="1" y="1" width="558" height="94" rx="12" fill="{CardBg}" stroke="{Border}" stroke-width="1.5"/>""");
        sb.Append($"""<rect x="1" y="1" width="558" height="4" rx="2" fill="{Band.Red.Hex()}"/>""");
        sb.Append($"""<text x="24" y="38" fill="{Ink}" font-size="20" font-weight="700">{Esc(projectName)}</text>""");
        sb.Append($"""<text x="24" y="60" fill="{Muted}" font-size="12.5">{Esc(subtitle ?? "")}</text>""");
        sb.Append($"""<text x="536" y="74" text-anchor="end" fill="{Band.Red.Hex()}" font-size="13" font-weight="700">no build ingested yet</text>""");
        sb.Append($"""<text x="24" y="84" font-size="10"><tspan fill="{Faint}">powered by </tspan><tspan fill="#8fa0bd" font-weight="600">tamp-findings</tspan><tspan fill="{Faint}"> · github.com/tamp-build</tspan></text>""");
        sb.Append("</svg>");
        return sb.ToString();
    }

    private static void Cell(StringBuilder sb, int x, int w, string hex, string label, string value, string suffix, int valueSize)
    {
        var v = valueSize.ToString(CultureInfo.InvariantCulture);
        var suffixSize = Math.Round(valueSize * 0.55).ToString(CultureInfo.InvariantCulture);
        sb.Append($"""<g transform="translate({x},74)">""");
        sb.Append($"""<rect width="{w}" height="82" rx="8" fill="{hex}" fill-opacity="0.10"/>""");
        sb.Append($"""<rect width="{w}" height="3" rx="1.5" fill="{hex}"/>""");
        sb.Append($"""<text x="12" y="26" fill="{Muted}" font-size="11" letter-spacing="0.3">{Esc(label)}</text>""");
        sb.Append($"""<text x="12" y="56" fill="{Ink}" font-size="{v}" font-weight="700">{Esc(value)}""");
        if (suffix.Length > 0) sb.Append($"""<tspan font-size="{suffixSize}" fill="#b7c2d4">{Esc(suffix)}</tspan>""");
        sb.Append("</text></g>");
    }

    private static string Num(double v) => v.ToString("0.#", CultureInfo.InvariantCulture);

    // The ship-gate sub-text, wrapped to at most two lines that fit the cell. One blocking gate wraps
    // its "Label · observed" over two lines; several collapse to a count so nothing overflows.
    private static (string? L1, string? L2) ShipSub(IReadOnlyList<string> reasons)
    {
        if (reasons.Count == 0) return (null, null);
        if (reasons.Count > 1)
        {
            var label = reasons[0].Split(" · ", 2)[0];
            return ($"{reasons.Count} gates blocking", Trunc(label, 24));
        }
        var lines = Wrap(reasons[0], 24);
        return (lines.ElementAtOrDefault(0), lines.ElementAtOrDefault(1));
    }

    private static List<string> Wrap(string text, int max)
    {
        var lines = new List<string>();
        var line = new StringBuilder();
        foreach (var word in text.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            if (line.Length > 0 && line.Length + 1 + word.Length > max)
            {
                lines.Add(line.ToString());
                line.Clear();
                if (lines.Count == 2) break;
            }
            if (line.Length > 0) line.Append(' ');
            line.Append(word);
        }
        if (lines.Count < 2 && line.Length > 0) lines.Add(line.ToString());
        if (lines.Count == 2 && line.Length > 0 && !lines[1].EndsWith(line.ToString(), StringComparison.Ordinal))
            lines[1] = Trunc(lines[1], max - 1) + "…";
        return lines;
    }

    private static string Trunc(string s, int max) => s.Length <= max ? s : s[..Math.Max(0, max - 1)] + "…";

    private static string Esc(string? s) => (s ?? "")
        .Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("\"", "&quot;");
}
