using Tamp.Findings.Build.Ingest;
using Tamp.Findings.Domain.Values;
using Tamp.Sbom;

namespace Tamp.Findings.Build.Adapters;

// Maps a parsed Tamp.Sbom CycloneDxBom → SbomIngestRequestDto. Folds the
// top-level CycloneDX Vulnerabilities array into per-component vuln
// lists by joining via affects.ref → component.bom-ref. CVE enrichment
// from a separate scanner (Grype) goes via a follow-up /ingest/sbom
// re-upload that supplies the vulnerabilities arrays.
public static class SbomIngestMapper
{
    public static SbomIngestRequestDto Map(CycloneDxBom bom, IngestBuildContext ctx)
    {
        var refToVulns = BuildRefToVulnsIndex(bom);

        var components = new List<SbomComponentDto>();
        if (bom.Components is not null)
        {
            foreach (var c in bom.Components)
            {
                if (string.IsNullOrWhiteSpace(c.Purl)) continue;

                var vulns = c.BomRef is not null && refToVulns.TryGetValue(c.BomRef, out var list)
                    ? list
                    : [];

                components.Add(new SbomComponentDto(
                    Purl: c.Purl,
                    Name: string.IsNullOrWhiteSpace(c.Name) ? "(unnamed)" : c.Name,
                    Version: string.IsNullOrWhiteSpace(c.Version) ? "(unversioned)" : c.Version,
                    Kind: c.Type,
                    License: c.Licenses?.FirstOrDefault()?.License?.Id
                          ?? c.Licenses?.FirstOrDefault()?.License?.Name
                          ?? c.Licenses?.FirstOrDefault()?.Expression,
                    Vulnerabilities: vulns));
            }
        }

        var dependencies = new List<SbomDependencyDto>();
        if (bom.Dependencies is not null && bom.Components is not null)
        {
            var refToPurl = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var c in bom.Components)
            {
                if (string.IsNullOrWhiteSpace(c.BomRef) || string.IsNullOrWhiteSpace(c.Purl)) continue;
                refToPurl[c.BomRef] = c.Purl;
            }

            foreach (var d in bom.Dependencies)
            {
                if (string.IsNullOrWhiteSpace(d.Ref)) continue;
                if (!refToPurl.TryGetValue(d.Ref, out var parentPurl)) continue;
                if (d.DependsOn is null) continue;
                foreach (var childRef in d.DependsOn)
                {
                    if (string.IsNullOrWhiteSpace(childRef)) continue;
                    if (!refToPurl.TryGetValue(childRef, out var childPurl)) continue;
                    dependencies.Add(new SbomDependencyDto(parentPurl, childPurl));
                }
            }
        }

        return new SbomIngestRequestDto(
            Client: ctx.Client,
            Project: ctx.Project,
            Component: ctx.Component,
            ComponentKind: ctx.ComponentKind,
            Flavor: ctx.Flavor,
            Version: ctx.Version,
            CommitSha: ctx.CommitSha,
            Branch: ctx.Branch,
            BuildId: ctx.BuildId,
            PullRequestRef: ctx.PullRequestRef,
            SerialNumber: bom.SerialNumber,
            SpecVersion: bom.SpecVersion,
            // Tamp.Sbom's minimal CycloneDxMetadata doesn't expose the tools
            // array; producer identity stays unknown for now.
            ToolName: null,
            ToolVersion: null,
            Components: components,
            Dependencies: dependencies);
    }

    private static Dictionary<string, List<VulnerabilityDto>> BuildRefToVulnsIndex(CycloneDxBom bom)
    {
        var map = new Dictionary<string, List<VulnerabilityDto>>(StringComparer.Ordinal);
        if (bom.Vulnerabilities is null) return map;

        foreach (var v in bom.Vulnerabilities)
        {
            if (string.IsNullOrWhiteSpace(v.Id)) continue;
            var sourceName = v.Source?.Name;
            var dto = new VulnerabilityDto(
                AdvisoryId: v.Id,
                Severity: MapSeverity(v.Ratings),
                Title: v.Description,
                Description: v.Detail ?? v.Description,
                FixedInVersion: null, // CycloneDX doesn't carry a single "fixedIn"; populate later via VEX/Affects analysis
                ReferenceUrl: v.Source?.Url,
                Source: InferScanner(sourceName));

            if (v.Affects is null) continue;
            foreach (var a in v.Affects)
            {
                if (string.IsNullOrWhiteSpace(a.Ref)) continue;
                if (!map.TryGetValue(a.Ref, out var list))
                {
                    list = [];
                    map[a.Ref] = list;
                }
                list.Add(dto);
            }
        }
        return map;
    }

    private static Severity MapSeverity(IReadOnlyList<CycloneDxVulnerabilityRating>? ratings)
    {
        if (ratings is null) return Severity.Info;
        // Use the highest-severity rating across providers.
        var max = Severity.Info;
        foreach (var r in ratings)
        {
            var mapped = r.Severity switch
            {
                CycloneDxSeverity.Critical => Severity.Critical,
                CycloneDxSeverity.High => Severity.High,
                CycloneDxSeverity.Medium => Severity.Medium,
                CycloneDxSeverity.Low => Severity.Low,
                CycloneDxSeverity.Info => Severity.Info,
                _ => Severity.Info,
            };
            if (mapped > max) max = mapped;
        }
        return max;
    }

    private static ScannerKind InferScanner(string? sourceName)
    {
        if (string.IsNullOrWhiteSpace(sourceName)) return ScannerKind.Unknown;
        var n = sourceName.ToLowerInvariant();
        if (n.Contains("osv")) return ScannerKind.OsvScanner;
        if (n.Contains("trivy")) return ScannerKind.Trivy;
        if (n.Contains("grype")) return ScannerKind.Grype;
        if (n.Contains("github") || n.Contains("ghsa")) return ScannerKind.Unknown;
        return ScannerKind.Unknown;
    }
}
