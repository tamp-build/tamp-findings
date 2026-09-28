using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using Tamp.Findings.Domain.Compliance;

namespace Tamp.Findings.Application.Compliance.Oscal;

/// <summary>
/// Parses a NIST OSCAL 1.2 control catalog (usnistgov/oscal-content) into the
/// domain's <see cref="Control"/> shape. The hard part is the statement: OSCAL
/// carries organization-defined parameters as <c>{{ insert: param, id }}</c>
/// markers referencing a params list, so the parser resolves each marker back to
/// the bracket form the rest of the product already speaks —
/// <c>[Assignment: …]</c> / <c>[Selection …]</c> — so
/// <see cref="ControlStatementParser"/> and the statement panel keep working
/// unchanged.
///
/// Baseline membership (Low/Moderate/High) is NOT in the catalog — it lives in
/// separate baseline profiles — so every control comes back with
/// <see cref="BaselineLevel.None"/>; a profile pass sets it afterwards.
/// </summary>
public static partial class OscalCatalogParser
{
    [GeneratedRegex(@"\{\{\s*insert:\s*param,\s*([A-Za-z0-9._-]+)\s*\}\}")]
    private static partial Regex InsertMarker();

    public sealed record ParsedCatalog(string Version, string OscalVersion, List<Control> Controls);

    public static ParsedCatalog Parse(Stream json)
    {
        var file = JsonSerializer.Deserialize<OscalFile>(json, Options)
            ?? throw new InvalidOperationException("empty OSCAL document");
        return Parse(file);
    }

    public static ParsedCatalog Parse(string json) =>
        Parse(JsonSerializer.Deserialize<OscalFile>(json, Options)
            ?? throw new InvalidOperationException("empty OSCAL document"));

    private static ParsedCatalog Parse(OscalFile file)
    {
        var cat = file.Catalog ?? throw new InvalidOperationException("no catalog in document");

        // A global param map: an insert usually references the control's own
        // param, but resolving globally is safe and handles catalog-level params.
        var paramsById = new Dictionary<string, OscalParam>(StringComparer.OrdinalIgnoreCase);
        foreach (var g in cat.Groups ?? [])
            foreach (var c in Flatten(g.Controls))
                foreach (var p in c.Params ?? [])
                    paramsById.TryAdd(p.Id, p);

        var controls = new List<Control>();
        foreach (var g in cat.Groups ?? [])
        {
            var family = g.Title ?? g.Id ?? "";
            foreach (var c in Flatten(g.Controls))
                controls.Add(new Control
                {
                    Id = DisplayId(c.Id),
                    Title = c.Title ?? c.Id ?? "",
                    Family = family,
                    Baselines = BaselineLevel.None,
                    StatementLines = StatementLines(c, paramsById),
                });
        }

        return new ParsedCatalog(
            cat.Metadata?.Version ?? "",
            cat.Metadata?.OscalVersion ?? "",
            controls);
    }

    // A control and all its nested enhancements, flattened.
    private static IEnumerable<OscalControl> Flatten(List<OscalControl>? controls)
    {
        foreach (var c in controls ?? [])
        {
            yield return c;
            foreach (var e in Flatten(c.Controls))
                yield return e;
        }
    }

    /// <summary>"ac-1" → "AC-1"; "ac-2.1" → "AC-2(1)" (enhancement). Public so a
    /// baseline profile's original-form ids can be matched to parsed controls.</summary>
    public static string DisplayId(string? id)
    {
        if (string.IsNullOrEmpty(id)) return "";
        var dot = id.IndexOf('.');
        if (dot < 0) return id.ToUpperInvariant();
        return id[..dot].ToUpperInvariant() + "(" + id[(dot + 1)..] + ")";
    }

    private static List<string> StatementLines(OscalControl c, Dictionary<string, OscalParam> paramsById)
    {
        var stmt = (c.Parts ?? []).FirstOrDefault(p => p.Name == "statement");
        if (stmt is null) return [];

        var lines = new List<string>();
        Emit(stmt, isRoot: true);
        return lines;

        void Emit(OscalPart part, bool isRoot)
        {
            var label = Label(part);
            var prose = Resolve(part.Prose, paramsById);
            // The statement root's own prose is the lead-in line; item parts get
            // their label ("a.", "1.") prepended.
            if (!string.IsNullOrWhiteSpace(prose))
                lines.Add(label is { Length: > 0 } ? $"{label} {prose}" : prose);
            else if (!isRoot && label is { Length: > 0 } && (part.Parts?.Count ?? 0) > 0)
                lines.Add(label); // a labelled group with no prose of its own

            foreach (var sub in part.Parts ?? [])
                if (sub.Name is "item" or "statement" or null)
                    Emit(sub, isRoot: false);
        }
    }

    private static string? Label(OscalPart part) =>
        (part.Props ?? []).FirstOrDefault(p => p.Name == "label")?.Value;

    // Replace {{ insert: param, id }} markers with the bracket form the domain
    // parser reads. Selections may nest assignments, resolved recursively.
    private static string Resolve(string? prose, Dictionary<string, OscalParam> paramsById)
    {
        if (string.IsNullOrEmpty(prose)) return "";
        return InsertMarker().Replace(prose, m =>
        {
            var id = m.Groups[1].Value;
            if (!paramsById.TryGetValue(id, out var p)) return "[Assignment: organization-defined value]";
            return Render(p, paramsById);
        });
    }

    private static string Render(OscalParam p, Dictionary<string, OscalParam> paramsById)
    {
        if (p.Select is { } sel)
        {
            var how = sel.HowMany == "one-or-more" ? " (one or more)" : "";
            var choices = (sel.Choice ?? []).Select(ch => Resolve(ch, paramsById));
            return $"[Selection{how}: {string.Join("; ", choices)}]";
        }
        var label = string.IsNullOrWhiteSpace(p.Label) ? "organization-defined value" : p.Label!;
        return $"[Assignment: {label}]";
    }

    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNameCaseInsensitive = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    // ---- OSCAL DTO subset (only what the parser reads) ----
    private sealed class OscalFile { public OscalCatalog? Catalog { get; set; } }
    private sealed class OscalCatalog { public OscalMetadata? Metadata { get; set; } public List<OscalGroup>? Groups { get; set; } }
    private sealed class OscalMetadata { public string? Version { get; set; } [JsonPropertyName("oscal-version")] public string? OscalVersion { get; set; } }
    private sealed class OscalGroup { public string? Id { get; set; } public string? Title { get; set; } public List<OscalControl>? Controls { get; set; } }
    private sealed class OscalControl
    {
        public string? Id { get; set; }
        public string? Title { get; set; }
        public List<OscalParam>? Params { get; set; }
        public List<OscalPart>? Parts { get; set; }
        public List<OscalControl>? Controls { get; set; }   // enhancements
    }
    private sealed class OscalParam { public string Id { get; set; } = ""; public string? Label { get; set; } public OscalSelect? Select { get; set; } }
    private sealed class OscalSelect { [JsonPropertyName("how-many")] public string? HowMany { get; set; } public List<string>? Choice { get; set; } }
    private sealed class OscalPart
    {
        public string? Id { get; set; }
        public string? Name { get; set; }
        public string? Prose { get; set; }
        public List<OscalProp>? Props { get; set; }
        public List<OscalPart>? Parts { get; set; }
    }
    private sealed class OscalProp { public string? Name { get; set; } public string? Value { get; set; } }
}
