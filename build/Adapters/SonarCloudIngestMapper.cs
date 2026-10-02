using System.Text.Json;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Build.Adapters;

// Maps SonarQube Cloud API responses (TFND-227) onto the findings ingest contracts. Pure functions over
// JsonElement so they are testable without the network: the HTTP half lives in SonarCloudClient.
//
// Typed routing is findings' job (FindingTypes): this only has to carry the Sonar issue TYPE on
// SubCategory — bug / code_smell / vulnerability / security_hotspot — and findings routes a code smell
// to the quality bucket and a vulnerability or hotspot to SAST, whatever the severity says.
public static class SonarCloudIngestMapper
{
    public static IReadOnlyList<IngestFindingDto> MapIssues(IEnumerable<JsonElement> issues, string projectKey) =>
        issues.Select(i => MapIssue(i, projectKey)).Where(f => f is not null).Select(f => f!).ToList();

    public static IReadOnlyList<IngestFindingDto> MapHotspots(IEnumerable<JsonElement> hotspots, string projectKey) =>
        hotspots.Select(h => MapHotspot(h, projectKey)).Where(f => f is not null).Select(f => f!).ToList();

    private static IngestFindingDto? MapIssue(JsonElement i, string projectKey)
    {
        var rule = Str(i, "rule");
        if (rule is null) return null;
        var type = Str(i, "type") switch
        {
            "BUG" => FindingTypes.Bug,
            "VULNERABILITY" => FindingTypes.Vulnerability,
            "SECURITY_HOTSPOT" => FindingTypes.SecurityHotspot,
            _ => FindingTypes.CodeSmell,
        };
        return new IngestFindingDto(
            RuleId: rule,
            Severity: IssueSeverity(Str(i, "severity")),
            Title: Truncate(Str(i, "message") ?? rule, 500),
            Description: null,
            FilePath: FilePath(Str(i, "component"), projectKey),
            Line: Int(i, "line"),
            Snippet: null,
            SubCategory: type);
    }

    private static IngestFindingDto? MapHotspot(JsonElement h, string projectKey)
    {
        var rule = Str(h, "ruleKey");
        if (rule is null) return null;
        return new IngestFindingDto(
            RuleId: rule,
            Severity: HotspotSeverity(Str(h, "vulnerabilityProbability")),
            Title: Truncate(Str(h, "message") ?? rule, 500),
            Description: Str(h, "securityCategory") is { } cat ? $"security category: {cat}" : null,
            FilePath: FilePath(Str(h, "component"), projectKey),
            Line: Int(h, "line"),
            Snippet: null,
            SubCategory: FindingTypes.SecurityHotspot);
    }

    // Sonar's legacy five-level severity onto ours. BLOCKER and CRITICAL are the two that can fail a gate.
    public static Severity IssueSeverity(string? s) => s switch
    {
        "BLOCKER" => Severity.Critical,
        "CRITICAL" => Severity.High,
        "MAJOR" => Severity.Medium,
        "MINOR" => Severity.Low,
        "INFO" => Severity.Info,
        _ => Severity.Medium,
    };

    // A hotspot has no severity, only the probability that it is a real vulnerability once reviewed.
    public static Severity HotspotSeverity(string? probability) => probability switch
    {
        "HIGH" => Severity.High,
        "MEDIUM" => Severity.Medium,
        _ => Severity.Low,
    };

    /// <summary>The quality-gate verdict ("OK"/"ERROR"/"WARN" on Sonar's side) and its conditions.</summary>
    public static (string Status, IReadOnlyList<QualityGateConditionIngestDto> Conditions) MapQualityGate(JsonElement projectStatus)
    {
        var status = Str(projectStatus, "status") switch
        {
            "OK" => "pass",
            "ERROR" => "fail",
            "WARN" => "warn",
            _ => "warn",   // NONE / unknown: not a pass, not a block
        };
        var conditions = new List<QualityGateConditionIngestDto>();
        if (projectStatus.TryGetProperty("conditions", out var cs) && cs.ValueKind == JsonValueKind.Array)
            foreach (var c in cs.EnumerateArray())
                conditions.Add(new QualityGateConditionIngestDto(
                    Metric: Str(c, "metricKey") ?? "",
                    Op: Str(c, "comparator"),
                    Threshold: Str(c, "errorThreshold"),
                    Actual: Str(c, "actualValue"),
                    Status: Str(c, "status") switch { "OK" => "pass", "ERROR" => "fail", "WARN" => "warn", var o => o?.ToLowerInvariant() }));
        return (status, conditions);
    }

    /// <summary>Headline measures as a flat object for the quality panel.</summary>
    public static Dictionary<string, string> MapMeasures(JsonElement measuresResponse)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        if (measuresResponse.TryGetProperty("component", out var comp)
            && comp.TryGetProperty("measures", out var ms) && ms.ValueKind == JsonValueKind.Array)
            foreach (var m in ms.EnumerateArray())
                if (Str(m, "metric") is { } k && Str(m, "value") is { } v) result[k] = v;
        return result;
    }

    // A component key is "<projectKey>:<path>"; findings stores the repo-relative path.
    internal static string? FilePath(string? component, string projectKey)
    {
        if (string.IsNullOrWhiteSpace(component)) return null;
        var prefix = projectKey + ":";
        var path = component.StartsWith(prefix, StringComparison.Ordinal) ? component[prefix.Length..] : component;
        // The project itself (no file) is reported with the bare key.
        return path == projectKey ? null : path;
    }

    private static string? Str(JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    private static int? Int(JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetInt32(out var n) ? n : null;

    private static string Truncate(string s, int max) => s.Length <= max ? s : s[..max];
}

// Wire shape of POST /ingest/quality-gate (Api.Contracts.QualityGateIngestRequest), restated here
// because the build never references the API assembly.
public sealed record QualityGateIngestRequestDto(
    string Client,
    string Project,
    string? Flavor,
    string Version,
    string? CommitSha,
    string? Branch,
    string? BuildId,
    string? PullRequestRef,
    string Status,
    IReadOnlyList<QualityGateConditionIngestDto>? Conditions,
    string? AnalysisId,
    Dictionary<string, string>? Measures,
    string? Source = null,
    DateTimeOffset? ObservedAt = null,
    IngestActorDto? Actor = null);

public sealed record QualityGateConditionIngestDto(string Metric, string? Op, string? Threshold, string? Actual, string? Status);
