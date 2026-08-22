using Tamp.Findings.Build.Ingest;
using Tamp.Findings.Domain.Values;
using Tamp.Sarif;

namespace Tamp.Findings.Build.Adapters;

// Maps a parsed Tamp.Sarif SarifLog → zero or more IngestRequestDto
// (one per SARIF run, since runs may come from different scanners after
// SarifMerge.CombineDistinct).
public static class SarifIngestMapper
{
    public static IEnumerable<IngestRequestDto> Map(SarifLog log, IngestBuildContext ctx)
    {
        if (log.Runs is null) yield break;

        // A merged SARIF (sast.sarif from SarifMerge.CombineDistinct) carries
        // separate runs for OpenGrep + per-(project, TFM) Roslyn outputs. All
        // Roslyn runs collapse to scanner=Roslyn here, so we group runs by
        // inferred scanner and post ONE IngestRequest per scanner with ALL
        // findings merged. Without this, each per-run POST would auto-close
        // (TFND-6 / F5.4) findings only present in sibling runs because the
        // ingest endpoint scopes auto-close to (componentVersion, scanner).
        var byScanner = new Dictionary<ScannerKind, List<IngestFindingDto>>();
        foreach (var run in log.Runs)
        {
            if (run.Results is null || run.Results.Count == 0) continue;
            var scanner = InferScanner(run.Tool?.Driver?.Name);
            if (!byScanner.TryGetValue(scanner, out var bucket))
            {
                bucket = [];
                byScanner[scanner] = bucket;
            }

            foreach (var r in run.Results)
            {
                var loc = r.Locations?.FirstOrDefault();
                var artifact = loc?.PhysicalLocation?.ArtifactLocation?.Uri;
                var region = loc?.PhysicalLocation?.Region;
                // TFND-17: Trivy folds three classes of findings under one
                // scanner name. Tamp.Sarif doesn't expose rule.properties.tags,
                // so we infer from RuleId prefix. Non-Trivy scanners get null.
                // TFND-27: AxeCore findings all get sub-category "accessibility"
                // so the SSDF attestation + dashboard can split them out.
                var subCategory = scanner switch
                {
                    ScannerKind.AxeCore => "accessibility",
                    // TFND-38: dynamic scanners share one bucket so the
                    // dashboard and SSDF PW.8.1 can split runtime-observed
                    // findings from static ones regardless of which DAST
                    // tool produced them.
                    ScannerKind.Zap or ScannerKind.Nuclei => "dast",
                    _ => InferTrivySubCategory(scanner, r.RuleId),
                };

                // ESLint embeds the source-snippet + line context in
                    // message.text — can hit 1k+ chars. The Finding.Title column
                    // is varchar(512); truncate to first line + clip so we stay
                    // safely under, while the full text rides in Description
                    // (text column, unlimited).
                    var rawMsg = r.Message?.Text;
                    var title = ShortTitle(rawMsg) ?? r.RuleId ?? "(no title)";
                bucket.Add(new IngestFindingDto(
                    RuleId: r.RuleId ?? "(unknown)",
                    Severity: MapSeverity(r.Level),
                    Title: title,
                    Description: rawMsg,
                    FilePath: artifact,
                    Line: region?.StartLine,
                    // Tamp.Sarif's minimal model doesn't surface snippets;
                    // dedup will fall back to (scanner, rule, path) only.
                    Snippet: null,
                    SubCategory: subCategory));
            }
        }

        foreach (var (scanner, findings) in byScanner)
        {
            if (findings.Count == 0) continue;
            yield return new IngestRequestDto(
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
                Scanner: scanner,
                Findings: findings);
        }
    }

    private static ScannerKind InferScanner(string? toolDriverName)
    {
        if (string.IsNullOrWhiteSpace(toolDriverName)) return ScannerKind.Unknown;
        var n = toolDriverName.ToLowerInvariant();

        if (n.Contains("opengrep") || n.Contains("semgrep")) return ScannerKind.OpenGrep;
        if (n.Contains("trivy")) return ScannerKind.Trivy;
        if (n.Contains("trufflehog")) return ScannerKind.TruffleHog;
        if (n.Contains("codeql")) return ScannerKind.CodeQL;
        if (n.Contains("osv")) return ScannerKind.OsvScanner;
        if (n.Contains("checkov")) return ScannerKind.Checkov;
        // JetBrains InspectCode (CLI of ReSharper). Emits SARIF with
        // tool.driver.name typically "InspectCode" or "ReSharper".
        if (n.Contains("inspectcode") || n.Contains("resharper") || n.Contains("jetbrains")) return ScannerKind.ReSharper;
        if (n.Contains("sonar") || n.Contains("roslyn") || n.Contains("roslynator")) return ScannerKind.Roslyn;
        // Roslyn analyzers (SonarAnalyzer.CSharp, Roslynator, etc.) emit SARIF
        // through the C# compiler; tool.driver.name is always the compiler.
        if (n.Contains("c# compiler") || n.Contains("csc") || n.Contains("microsoft (r) visual")) return ScannerKind.Roslyn;
        if (n.Contains("stryker")) return ScannerKind.Stryker;
        // ESLint SARIF via @microsoft/eslint-formatter-sarif sets
        // tool.driver.name to "ESLint".
        if (n.Contains("eslint")) return ScannerKind.ESLint;
        // TFND-27: axe-sarif-converter sets tool.driver.name to "axe"
        // (sometimes "axe-core"); covers both with one contains check.
        if (n.Contains("axe")) return ScannerKind.AxeCore;
        // ZAP sets tool.driver.name to "ZAP" (historically "OWASP ZAP");
        // match on the substring so both land on the same kind.
        if (n.Contains("zap")) return ScannerKind.Zap;
        if (n.Contains("nuclei")) return ScannerKind.Nuclei;
        return ScannerKind.Unknown;
    }

    // Pulls the first line of the SARIF message (the actual sentence)
    // and clips to 500 chars with an ellipsis so the result always fits
    // Finding.Title's varchar(512).
    private static string? ShortTitle(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;
        var nl = raw.IndexOf('\n');
        var firstLine = (nl >= 0 ? raw[..nl] : raw).TrimEnd('\r', ' ');
        return firstLine.Length <= 500 ? firstLine : firstLine[..497] + "…";
    }

    private static Severity MapSeverity(SarifLevel level) => level switch
    {
        SarifLevel.Error => Severity.High,
        SarifLevel.Warning => Severity.Medium,
        SarifLevel.Note => Severity.Low,
        _ => Severity.Info,
    };

    // Trivy rule-id prefix → sub-category. Heuristic only; Tamp.Sarif doesn't
    // expose the rule's `tags` property where Trivy explicitly marks
    // {vulnerability,misconfiguration,secret,license}.
    private static string? InferTrivySubCategory(ScannerKind scanner, string? ruleId)
    {
        if (scanner != ScannerKind.Trivy || string.IsNullOrEmpty(ruleId)) return null;
        if (ruleId.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase)) return "vulnerability";
        if (ruleId.StartsWith("GHSA-", StringComparison.OrdinalIgnoreCase)) return "vulnerability";
        if (ruleId.StartsWith("AVD-", StringComparison.OrdinalIgnoreCase)) return "misconfiguration";
        if (ruleId.StartsWith("DS", StringComparison.OrdinalIgnoreCase)) return "misconfiguration"; // Dockerfile rules
        if (ruleId.StartsWith("KSV", StringComparison.OrdinalIgnoreCase)) return "misconfiguration"; // K8s
        // Trivy's built-in secret detector emits short alphabetic rule IDs
        // ("aws-access-key-id", "github-pat", etc.). Default fallback for
        // anything else under Trivy is secret.
        return "secret";
    }
}
