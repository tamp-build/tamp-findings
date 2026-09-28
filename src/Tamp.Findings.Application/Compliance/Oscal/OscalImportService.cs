using Tamp.Findings.Domain.Compliance;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Application.Compliance.Oscal;

/// <summary>
/// Builds a <see cref="ControlCatalog"/> from an OSCAL 1.2 catalog plus its
/// baseline profiles (v3 §6 / TFND-180). The catalog supplies the control text +
/// parameters; each profile supplies which controls belong to a baseline
/// (Low/Moderate/High), so membership is REAL — read from the profile, not
/// approximated. Pure (no I/O beyond the streams); the caller persists the result.
/// </summary>
public sealed class OscalImportService
{
    public const string CatalogName = "NIST SP 800-53 Rev 5";

    /// <param name="catalog">The OSCAL catalog JSON stream.</param>
    /// <param name="profiles">Baseline level → that baseline's profile JSON stream.</param>
    /// <param name="source">Provenance text for the catalog row.</param>
    /// <param name="importedSha">Optional content hash of the catalog.</param>
    public ControlCatalog BuildCatalog(
        Stream catalog,
        IReadOnlyDictionary<BaselineLevel, Stream> profiles,
        string source,
        string? importedSha = null)
    {
        var parsed = OscalCatalogParser.Parse(catalog);

        // Each profile's control ids, mapped to the display form the parsed
        // controls carry ("ac-2.1" → "AC-2(1)").
        var membership = new Dictionary<BaselineLevel, HashSet<string>>();
        foreach (var (level, stream) in profiles)
            membership[level] = OscalProfileParser.Parse(stream)
                .Select(OscalCatalogParser.DisplayId)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (var c in parsed.Controls)
        {
            var b = BaselineLevel.None;
            foreach (var (level, ids) in membership)
                if (ids.Contains(c.Id))
                    b |= level;
            c.Baselines = b;
        }

        return new ControlCatalog
        {
            Name = $"{CatalogName} {parsed.Version}".TrimEnd(),
            Source = source,
            Version = string.IsNullOrWhiteSpace(parsed.Version) ? "unknown" : parsed.Version,
            OscalVersion = string.IsNullOrWhiteSpace(parsed.OscalVersion) ? null : parsed.OscalVersion,
            ImportedSha = importedSha,
            IsSeeded = true,
            IsCurrent = true,
            Controls = parsed.Controls,
        };
    }
}
