using System.Text.RegularExpressions;
using Tamp;
using Tamp.Findings.Build.Ingest;
using Tamp.Findings.Domain.Values;
using Tamp.Sarif;

namespace Tamp.Findings.Build.Adapters;

// Parses osv-scanner's SARIF output into structured (package, version,
// advisoryId, severity) records so they can be folded into SbomComponent.
// Vulnerabilities — addresses TFND-16's "OsvScanner findings should reach
// the SBOM ring" gap.
//
// OsvScanner's SARIF puts package identity in the result message text
// using the canonical "Package 'name@version' is vulnerable to 'ID'…"
// format. We pull the name+version pair out via regex and use the ruleId
// as the advisory id. CVSS lives on the rule's properties.security-severity.
public static class OsvScannerCveSarifMapper
{
    private static readonly Regex PackageInMessage = new(
        @"Package\s+'(?<name>[^@']+)@(?<version>[^']+)'",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    public static IReadOnlyList<OsvVulnerabilityDto> Map(string sarifPath)
    {
        if (!File.Exists(sarifPath)) return [];
        SarifLog log;
        try { log = SarifReader.LoadFromFile(AbsolutePath.Create(sarifPath)); }
        catch { return []; }

        // Index rules by id so we can pull title / help-uri per finding.
        // Tamp.Sarif's minimal SarifRule doesn't surface raw `properties`,
        // so we lose access to OsvScanner's `security-severity` CVSS field;
        // severity falls back to the SARIF level (warning = Medium).
        var ruleIndex = new Dictionary<string, SarifRule>(StringComparer.OrdinalIgnoreCase);
        foreach (var run in log.Runs ?? [])
        {
            foreach (var rule in run.Tool?.Driver?.Rules ?? [])
            {
                if (!string.IsNullOrEmpty(rule.Id) && !ruleIndex.ContainsKey(rule.Id))
                    ruleIndex[rule.Id] = rule;
            }
        }

        var results = new List<OsvVulnerabilityDto>();
        foreach (var run in log.Runs ?? [])
        {
            foreach (var r in run.Results ?? [])
            {
                if (string.IsNullOrEmpty(r.RuleId)) continue;
                var text = r.Message?.Text ?? "";
                var m = PackageInMessage.Match(text);
                if (!m.Success) continue;

                var name = m.Groups["name"].Value;
                var version = m.Groups["version"].Value;
                ruleIndex.TryGetValue(r.RuleId, out var rule);
                var severity = MapSeverity(r.Level);
                var title = rule?.ShortDescription?.Text ?? r.Message?.Text;
                var description = rule?.FullDescription?.Text;
                var referenceUrl = !string.IsNullOrWhiteSpace(rule?.HelpUri)
                    ? rule.HelpUri
                    : FirstUrl(rule?.FullDescription?.Text);

                results.Add(new OsvVulnerabilityDto(
                    PackageName: name,
                    PackageVersion: version,
                    AdvisoryId: r.RuleId,
                    Severity: severity,
                    Title: title,
                    Description: description,
                    ReferenceUrl: referenceUrl));
            }
        }
        return results;
    }

    private static Severity MapSeverity(SarifLevel level) => level switch
    {
        SarifLevel.Error => Severity.High,
        SarifLevel.Warning => Severity.Medium,
        SarifLevel.Note => Severity.Low,
        _ => Severity.Info,
    };

    private static readonly Regex UrlPattern = new(@"https?://\S+", RegexOptions.Compiled);
    private static string? FirstUrl(string? text)
    {
        if (string.IsNullOrEmpty(text)) return null;
        var m = UrlPattern.Match(text);
        return m.Success ? m.Value.TrimEnd('.', ',', ')', ']') : null;
    }
}

public sealed record OsvVulnerabilityDto(
    string PackageName,
    string PackageVersion,
    string AdvisoryId,
    Severity Severity,
    string? Title,
    string? Description,
    string? ReferenceUrl);

public sealed record OsvVulnerabilityUpsertRequestDto(
    Guid SnapshotId,
    IReadOnlyList<OsvVulnerabilityDto> Vulnerabilities);
