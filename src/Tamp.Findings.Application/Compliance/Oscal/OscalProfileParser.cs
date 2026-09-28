using System.Text.Json;
using System.Text.Json.Serialization;

namespace Tamp.Findings.Application.Compliance.Oscal;

/// <summary>
/// Parses an OSCAL baseline profile (e.g. NIST 800-53B Low/Moderate/High) into
/// the set of control ids it selects. Baseline membership is what a profile
/// contributes — the catalog carries the control text, the profile says which
/// controls are in the baseline. Ids come back in the catalog's original form
/// ("ac-1", "ac-2.1"); the importer maps them to display ids.
/// </summary>
public static class OscalProfileParser
{
    public static IReadOnlyCollection<string> Parse(Stream json) =>
        Collect(JsonSerializer.Deserialize<OscalProfileFile>(json, Options));

    public static IReadOnlyCollection<string> Parse(string json) =>
        Collect(JsonSerializer.Deserialize<OscalProfileFile>(json, Options));

    private static IReadOnlyCollection<string> Collect(OscalProfileFile? file)
    {
        var ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var imp in file?.Profile?.Imports ?? [])
            foreach (var inc in imp.IncludeControls ?? [])
                foreach (var id in inc.WithIds ?? [])
                    if (!string.IsNullOrWhiteSpace(id))
                        ids.Add(id);
        return ids;
    }

    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNameCaseInsensitive = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    private sealed class OscalProfileFile { public OscalProfile? Profile { get; set; } }
    private sealed class OscalProfile { public List<OscalImport>? Imports { get; set; } }
    private sealed class OscalImport
    {
        [JsonPropertyName("include-controls")] public List<OscalIncludeControls>? IncludeControls { get; set; }
    }
    private sealed class OscalIncludeControls
    {
        [JsonPropertyName("with-ids")] public List<string>? WithIds { get; set; }
    }
}
