using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Ingest;

namespace Tamp.Findings.Integration.Tests;

/// <summary>Drives the real ingest endpoints with the golden v1 fixtures to build a realistically populated build.</summary>
public static class PageAIngest
{
    private static string FixtureDir()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            var candidate = Path.Combine(dir.FullName, "tests", "Fixtures", "Ingest", "v1");
            if (Directory.Exists(candidate)) return candidate;
            dir = dir.Parent;
        }
        throw new DirectoryNotFoundException("tests/Fixtures/Ingest/v1 not found above " + AppContext.BaseDirectory);
    }

    public static async Task<string> MintTokenAsync(DatabaseFixture fx, Guid projectId, Guid userId)
    {
        using var scope = fx.Scope();
        return (await scope.ServiceProvider.GetRequiredService<IngestTokenService>()
            .MintProjectTokenAsync(projectId, "pagea-tok", userId, default)).Plaintext;
    }

    private static JsonNode Load(string file, string client, string project, string sha, string version)
    {
        var node = JsonNode.Parse(File.ReadAllText(Path.Combine(FixtureDir(), file)))!;
        node["client"] = client;
        node["project"] = project;
        node["commitSha"] = sha;
        node["version"] = version;
        node["flavor"] = null;
        NumericNullsToZero(node);
        return node;
    }

    // The golden coverage fixtures carry nulls for metrics the contract declares non-nullable.
    private static void NumericNullsToZero(JsonNode? n)
    {
        if (n is JsonObject o)
        {
            foreach (var key in o.Select(kv => kv.Key).ToList())
            {
                if (o[key] is null && (key.Contains("overage", StringComparison.Ordinal) || key.StartsWith("covered", StringComparison.Ordinal)
                    || key.StartsWith("total", StringComparison.Ordinal))) o[key] = 0;
                else NumericNullsToZero(o[key]);
            }
        }
        else if (n is JsonArray a) foreach (var x in a) NumericNullsToZero(x);
    }

    /// <summary>Ingests every fixture kind for one build. Returns the SBOM snapshot id.</summary>
    public static async Task<Guid> IngestBuildAsync(
        DatabaseFixture fx, PageAWorld w, string sha, string version = "1.0.0", bool full = true)
    {
        var token = await MintTokenAsync(fx, w.Project.Id, w.Admin.Id);
        var http = fx.Factory!.CreateClient();
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        var client = w.Client.Name;
        var project = w.Project.Name;

        async Task<JsonDocument> Post(string url, JsonNode body)
        {
            var resp = await http.PostAsJsonAsync(url, body);
            var text = await resp.Content.ReadAsStringAsync();
            Assert.True(resp.IsSuccessStatusCode, $"POST {url} -> {(int)resp.StatusCode}: {text}");
            return JsonDocument.Parse(string.IsNullOrWhiteSpace(text) ? "{}" : text);
        }

        var sbom = await Post("/ingest/sbom", Load("01-sbom-request.json", client, project, sha, version));
        var snapshotId = Guid.Empty;
        foreach (var p in sbom.RootElement.EnumerateObject())
            if (p.Name.Equals("sbomSnapshotId", StringComparison.OrdinalIgnoreCase)) snapshotId = p.Value.GetGuid();

        await Post("/ingest/findings", Load("02-findings-roslyn-request.json", client, project, sha, version));
        if (!full) return snapshotId;
        await Post("/ingest/findings", Load("03-findings-eslint-request.json", client, project, sha, version));
        await Post("/ingest/findings", Load("04-findings-trivy-request.json", client, project, sha, version));
        await Post("/ingest/coverage", Load("05-coverage-dotnet-request.json", client, project, sha, version));
        await Post("/ingest/coverage", Load("06-coverage-vitest-request.json", client, project, sha, version));
        await Post("/ingest/test-results", Load("07-test-results-request.json", client, project, sha, version));
        await Post("/ingest/scan-runs", Load("08-scan-runs-request.json", client, project, sha, version));

        if (snapshotId != Guid.Empty)
        {
            var vuln = JsonNode.Parse(File.ReadAllText(Path.Combine(FixtureDir(), "09-sbom-vulnerabilities-upsert-request.json")))!;
            vuln["snapshotId"] = snapshotId.ToString();
            await Post("/sbom-vulnerabilities/upsert", vuln);
            foreach (var f in new[] { "10-sbom-provenance-slsa-request.json", "11-sbom-provenance-dsse-request.json" })
            {
                var prov = JsonNode.Parse(File.ReadAllText(Path.Combine(FixtureDir(), f)))!;
                var resp = await http.PostAsJsonAsync($"/ingest/sbom-snapshots/{snapshotId}/provenance", prov);
                _ = resp.StatusCode; // provenance verification outcomes vary; the build is populated either way
            }
        }
        return snapshotId;
    }
}
