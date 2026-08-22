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

            // TAM-279 made rule metadata reachable. Dynamic scanners put a
            // whole descriptive paragraph in message.text — ZAP's cache-control
            // finding runs to 300+ characters — which makes an unreadable
            // title in any list view. rule.name is the short human label
            // ("Re-examine Cache-control Directives"), so prefer it and let the
            // paragraph be the description.
            var ruleNames = run.Tool?.Driver?.Rules?
                .Where(x => !string.IsNullOrWhiteSpace(x.Id) && !string.IsNullOrWhiteSpace(x.Name))
                .GroupBy(x => x.Id, StringComparer.Ordinal)
                .ToDictionary(g => g.Key, g => g.First().Name!, StringComparer.Ordinal)
                ?? [];

            // rule.properties["security-severity"] is a CVSS-style score and
            // the GitHub code-scanning convention. It matters because SARIF's
            // own level vocabulary is error | warning | note | none — there is
            // no "critical", so a scanner reporting through levels alone can
            // never produce a Critical finding, and any "critical" gate over
            // it is dead. Where a scanner does publish a score, band from it.
            // Verified present on Trivy (5.5 -> MEDIUM, 2.0 -> LOW, matching
            // its own tags) and Nuclei; absent on ZAP, OpenGrep, ESLint,
            // Roslyn and ReSharper, which keep the level mapping.
            var ruleScores = new Dictionary<string, double>(StringComparer.Ordinal);
            foreach (var rule in run.Tool?.Driver?.Rules ?? [])
            {
                if (string.IsNullOrWhiteSpace(rule.Id)) continue;
                if (rule.Properties?.AdditionalProperties is not { } props) continue;
                if (!props.TryGetValue("security-severity", out var raw)) continue;

                var text = raw.ValueKind == System.Text.Json.JsonValueKind.String
                    ? raw.GetString()
                    : raw.ToString();
                if (double.TryParse(text, System.Globalization.NumberStyles.Float,
                        System.Globalization.CultureInfo.InvariantCulture, out var score))
                {
                    ruleScores[rule.Id] = score;
                }
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
                    var title = (ScannerKinds.IsDynamic(scanner)
                                    && r.RuleId is { } rid
                                    && ruleNames.TryGetValue(rid, out var ruleName)
                                        ? ruleName
                                        : null)
                                ?? ShortTitle(rawMsg)
                                ?? r.RuleId
                                ?? "(no title)";
                // Nuclei's SARIF export sets artifactLocation.uri to "." and
                // puts the scanned target in region.snippet instead, so the
                // route tree would group every finding under ".". Synthesise a
                // URL from the snippet so the finding lands on the host it was
                // actually observed against. https:// is an assumption, but
                // only the host and path participate in route identity — the
                // scheme is discarded by DastRoute.
                var dynamicPath = artifact;
                if (scanner is ScannerKind.Nuclei
                    && (string.IsNullOrWhiteSpace(artifact) || artifact == ".")
                    && r.Locations?.FirstOrDefault()?.PhysicalLocation?.Region?.Snippet?.Text is { Length: > 0 } target)
                {
                    dynamicPath = target.Contains("://", StringComparison.Ordinal)
                        ? target
                        : $"https://{target}";
                }

                bucket.Add(new IngestFindingDto(
                    RuleId: r.RuleId ?? "(unknown)",
                    Severity: r.RuleId is { } sevRule && ruleScores.TryGetValue(sevRule, out var cvss)
                        ? MapCvssSeverity(cvss)
                        : MapSeverity(r.Level),
                    Title: title,
                    Description: rawMsg,
                    FilePath: dynamicPath,
                    Line: region?.StartLine,
                    // TAM-279: Tamp.Sarif 1.14.0 models region.snippet, so
                    // dedup no longer falls back to (scanner, rule, path) plus
                    // a line number. This helps every SARIF scanner, not just
                    // the DAST ones — a line-based hash churns whenever code
                    // moves, a snippet-based one survives the edit.
                    Snippet: region?.Snippet?.Text,
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

    // CVSS v3 qualitative bands, the same split GitHub code scanning uses for
    // security-severity. A score is a stronger signal than a SARIF level
    // because the level vocabulary tops out at "error".
    private static Severity MapCvssSeverity(double score) => score switch
    {
        >= 9.0 => Severity.Critical,
        >= 7.0 => Severity.High,
        >= 4.0 => Severity.Medium,
        > 0.0  => Severity.Low,
        _      => Severity.Info,
    };

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
