using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Tamp.Findings.Build.Ingest;

// Tiny HTTP client the build orchestrator uses to POST ingest payloads
// at the locally-running tamp.findings API. Lives in build/ rather than
// in src/Tamp.Findings.Api so the API doesn't depend on its own consumer.
public sealed class IngestClient(string baseUrl)
{
    private readonly HttpClient _http = new() { BaseAddress = new Uri(baseUrl) };

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter() },
    };

    public async Task<JsonElement> PostFindingsAsync<TPayload>(TPayload payload, CancellationToken ct = default)
    {
        var resp = await _http.PostAsJsonAsync("/ingest/findings", payload, JsonOptions, ct);
        return await ReadResponseAsync(resp, ct);
    }

    public async Task<JsonElement> PostSbomAsync<TPayload>(TPayload payload, CancellationToken ct = default)
    {
        var resp = await _http.PostAsJsonAsync("/ingest/sbom", payload, JsonOptions, ct);
        return await ReadResponseAsync(resp, ct);
    }

    public async Task<JsonElement> EnrichSbomVersionsAsync(Guid snapshotId, CancellationToken ct = default)
    {
        // Slow call (one HTTP roundtrip per dep against the public registries),
        // so a long timeout is appropriate. 5 minutes is overkill for 300 deps
        // at 8 concurrent, but keeps the cliff far away from real workloads.
        var http = new HttpClient { BaseAddress = _http.BaseAddress, Timeout = TimeSpan.FromMinutes(5) };
        var resp = await http.PostAsync($"/sbom-components/enrich-versions?snapshotId={snapshotId}", content: null, ct);
        return await ReadResponseAsync(resp, ct);
    }

    private static async Task<JsonElement> ReadResponseAsync(HttpResponseMessage resp, CancellationToken ct)
    {
        var body = await resp.Content.ReadAsStringAsync(ct);
        if (!resp.IsSuccessStatusCode)
        {
            throw new InvalidOperationException(
                $"ingest call returned {(int)resp.StatusCode} {resp.ReasonPhrase}: {body}");
        }
        return JsonDocument.Parse(body).RootElement.Clone();
    }
}
