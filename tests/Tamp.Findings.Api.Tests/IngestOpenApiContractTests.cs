using System.Net.Http.Json;
using System.Text.Json;

namespace Tamp.Findings.Api.Tests;

// TFND-266: every /ingest/* route returns a body describing what was stored, but the OpenAPI document used to say
// only "200 OK", so producers and generated clients believed there was nothing to read. This walks the published
// document, so a new ingest route that forgets to declare its response fails here rather than in a customer's CI.
public class IngestOpenApiContractTests : IClassFixture<TestApiFactory>
{
    private readonly TestApiFactory _factory;
    public IngestOpenApiContractTests(TestApiFactory factory) => _factory = factory;

    // Routes whose evidence is not attached to a build named by the request's commit: posture is project-scoped,
    // conformance / diagnostics bind each event to the build named in its own envelope, and provenance is addressed
    // by the SBOM snapshot id /ingest/sbom returned.
    private static readonly HashSet<string> NotSingleBuild =
        ["/ingest/posture", "/ingest/conformance", "/ingest/diagnostics", "/ingest/sbom-snapshots/{snapshotId}/provenance"];

    private async Task<List<(string Path, JsonElement Post)>> IngestPostsAsync()
    {
        var doc = await _factory.CreateClient().GetFromJsonAsync<JsonElement>("/openapi/v1.json");
        return doc.GetProperty("paths").EnumerateObject()
            .Where(p => p.Name.StartsWith("/ingest/", StringComparison.Ordinal) && p.Value.TryGetProperty("post", out _))
            .Select(p => (p.Name, p.Value.GetProperty("post")))
            .ToList();
    }

    [Fact]
    public async Task There_are_ingest_routes_to_check()
    {
        // Guards the other tests against passing vacuously if the document shape changes.
        Assert.True((await IngestPostsAsync()).Count >= 15);
    }

    [Fact]
    public async Task Every_ingest_route_declares_the_body_its_200_returns()
    {
        var missing = (await IngestPostsAsync())
            .Where(r => !(r.Post.GetProperty("responses").TryGetProperty("200", out var ok)
                          && ok.TryGetProperty("content", out var content)
                          && content.EnumerateObject().Any(c => c.Value.TryGetProperty("schema", out _))))
            .Select(r => r.Path)
            .ToList();

        Assert.True(missing.Count == 0, "ingest routes whose 200 has no schema: " + string.Join(", ", missing));
    }

    [Fact]
    public async Task Every_single_build_ingest_states_the_build_identity_rule()
    {
        var missing = (await IngestPostsAsync())
            .Where(r => !NotSingleBuild.Contains(r.Path))
            .Where(r => !(r.Post.TryGetProperty("summary", out var s) && s.GetString()!.Contains("Build identity:", StringComparison.Ordinal)))
            .Select(r => r.Path)
            .ToList();

        Assert.True(missing.Count == 0, "single-build ingest routes without the build-identity rule: " + string.Join(", ", missing));
    }

    [Fact]
    public async Task Single_build_ingest_responses_document_the_resolved_build()
    {
        var doc = await _factory.CreateClient().GetFromJsonAsync<JsonElement>("/openapi/v1.json");
        var schemas = doc.GetProperty("components").GetProperty("schemas");

        Assert.True(schemas.TryGetProperty("ResolvedBuild", out var rb), "ResolvedBuild schema missing");
        Assert.True(rb.GetProperty("properties").TryGetProperty("commitSha", out _));
        Assert.True(schemas.GetProperty("CoverageIngestResponse").GetProperty("properties").TryGetProperty("build", out _));
    }

    [Fact]
    public async Task No_ingest_summary_carries_mangled_punctuation()
    {
        // Strata saw "cli_â€¦" in the document. The server's bytes are clean UTF-8 (that was a cp1252 decode on the
        // reading side), and this keeps it that way: no summary may contain a UTF-8 sequence re-read as cp1252.
        var bad = (await IngestPostsAsync())
            .Where(r => r.Post.TryGetProperty("summary", out var s) && (s.GetString()!.Contains("â€") || s.GetString()!.Contains("Ã")))
            .Select(r => r.Path)
            .ToList();

        Assert.Empty(bad);
    }
}
