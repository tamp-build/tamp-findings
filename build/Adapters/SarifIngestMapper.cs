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
                var subCategory = InferTrivySubCategory(scanner, r.RuleId);

                bucket.Add(new IngestFindingDto(
                    RuleId: r.RuleId ?? "(unknown)",
                    Severity: MapSeverity(r.Level),
                    Title: r.Message?.Text ?? r.RuleId ?? "(no title)",
                    Description: r.Message?.Text,
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
        return ScannerKind.Unknown;
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
