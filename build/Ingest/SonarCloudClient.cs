using System.Text.Json;

namespace Tamp.Findings.Build.Ingest;

// Reads a SonarQube Cloud project's analysis results over its public web API (TFND-227). The project is
// public, so reads work anonymously; a token is sent when one is available (it lifts rate limits and
// would also work for a private project). Read-only: nothing here writes to SonarCloud.
public sealed class SonarCloudClient
{
    private const int PageSize = 500;
    private const int MaxResults = 10_000;   // SonarCloud refuses to page past 10k results

    private readonly HttpClient _http;

    public SonarCloudClient(string baseUrl = "https://sonarcloud.io", string? token = null)
    {
        _http = new HttpClient { BaseAddress = new Uri(baseUrl), Timeout = TimeSpan.FromSeconds(60) };
        if (!string.IsNullOrWhiteSpace(token))
            _http.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
    }

    /// <summary>The most recent analysis of a branch: its revision (commit sha), date and key. Null when the
    /// branch has never been analysed.</summary>
    public async Task<SonarAnalysis?> LatestAnalysisAsync(string projectKey, string branch, CancellationToken ct = default)
    {
        var doc = await GetAsync($"/api/project_analyses/search?project={Uri.EscapeDataString(projectKey)}&branch={Uri.EscapeDataString(branch)}&ps=1", ct);
        if (doc is null || !doc.Value.TryGetProperty("analyses", out var a) || a.GetArrayLength() == 0) return null;
        var first = a[0];
        return new SonarAnalysis(
            first.GetProperty("key").GetString()!,
            first.TryGetProperty("revision", out var r) ? r.GetString() : null,
            DateTimeOffset.Parse(first.GetProperty("date").GetString()!));
    }

    public async Task<IReadOnlyList<JsonElement>> OpenIssuesAsync(string projectKey, string branch, CancellationToken ct = default) =>
        await PagedAsync(p => $"/api/issues/search?componentKeys={Uri.EscapeDataString(projectKey)}&branch={Uri.EscapeDataString(branch)}&resolved=false&ps={PageSize}&p={p}", "issues", ct);

    public async Task<IReadOnlyList<JsonElement>> OpenHotspotsAsync(string projectKey, string branch, CancellationToken ct = default) =>
        await PagedAsync(p => $"/api/hotspots/search?projectKey={Uri.EscapeDataString(projectKey)}&branch={Uri.EscapeDataString(branch)}&status=TO_REVIEW&ps={PageSize}&p={p}", "hotspots", ct);

    public async Task<JsonElement?> QualityGateAsync(string projectKey, string branch, CancellationToken ct = default)
    {
        var doc = await GetAsync($"/api/qualitygates/project_status?projectKey={Uri.EscapeDataString(projectKey)}&branch={Uri.EscapeDataString(branch)}", ct);
        return doc is { } d && d.TryGetProperty("projectStatus", out var ps) ? ps : null;
    }

    public async Task<JsonElement> MeasuresAsync(string projectKey, string branch, CancellationToken ct = default) =>
        await GetAsync($"/api/measures/component?component={Uri.EscapeDataString(projectKey)}&branch={Uri.EscapeDataString(branch)}"
            + "&metricKeys=ncloc,coverage,bugs,vulnerabilities,code_smells,security_hotspots,duplicated_lines_density", ct) ?? default;

    private async Task<IReadOnlyList<JsonElement>> PagedAsync(Func<int, string> url, string arrayName, CancellationToken ct)
    {
        var all = new List<JsonElement>();
        for (var page = 1; (page - 1) * PageSize < MaxResults; page++)
        {
            var doc = await GetAsync(url(page), ct);
            if (doc is null || !doc.Value.TryGetProperty(arrayName, out var arr) || arr.ValueKind != JsonValueKind.Array) break;
            all.AddRange(arr.EnumerateArray().Select(e => e.Clone()));
            var total = doc.Value.TryGetProperty("paging", out var paging) && paging.TryGetProperty("total", out var t) ? t.GetInt32() : all.Count;
            if (all.Count >= total || arr.GetArrayLength() == 0) break;
        }
        return all;
    }

    // 404 (unknown project or branch) is "nothing there", anything else non-2xx is a real failure.
    private async Task<JsonElement?> GetAsync(string url, CancellationToken ct)
    {
        using var resp = await _http.GetAsync(url, ct);
        if (resp.StatusCode == System.Net.HttpStatusCode.NotFound) return null;
        var body = await resp.Content.ReadAsStringAsync(ct);
        if (!resp.IsSuccessStatusCode)
            throw new InvalidOperationException($"SonarCloud {url} returned {(int)resp.StatusCode}: {body}");
        return JsonDocument.Parse(body).RootElement.Clone();
    }
}

public sealed record SonarAnalysis(string Key, string? Revision, DateTimeOffset Date);
