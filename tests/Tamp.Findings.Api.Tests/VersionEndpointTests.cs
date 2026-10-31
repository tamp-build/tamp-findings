using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Tamp.Findings.Application.Versioning;

namespace Tamp.Findings.Api.Tests;

// TFND-267: an instance must be able to say which build it runs — anonymously, in one machine-readable place,
// and consistently everywhere it is shown. Before this every instance's OpenAPI said "1.0.0" and /version returned
// the assembly's numeric 0.1.0.0, so two different builds were indistinguishable from outside.
public class VersionEndpointTests : IClassFixture<TestApiFactory>
{
    private readonly TestApiFactory _factory;
    public VersionEndpointTests(TestApiFactory factory) => _factory = factory;

    [Fact]
    public async Task Version_is_anonymous_and_reports_the_stamped_build()
    {
        var client = _factory.CreateClient();   // no credentials

        var resp = await client.GetAsync("/version");
        var body = await resp.Content.ReadFromJsonAsync<JsonElement>();

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var build = BuildInfo.Current;
        Assert.Equal("tamp.findings.api", body.GetProperty("service").GetString());   // unchanged for existing callers
        Assert.Equal(build.Version, body.GetProperty("version").GetString());
        Assert.Equal(build.Display, body.GetProperty("display").GetString());
        Assert.Equal(build.Commit, body.GetProperty("commit").GetString());
        Assert.StartsWith(".NET ", body.GetProperty("runtime").GetString());
        if (build.Commit is { } sha)
            Assert.EndsWith(sha, body.GetProperty("source").GetString());
    }

    [Theory]
    [InlineData("/version")]
    [InlineData("/health")]
    [InlineData("/openapi/v1.json")]
    [InlineData("/does-not-exist")]   // even a 404 says which build answered
    public async Task Every_response_names_the_build_in_a_header(string path)
    {
        var resp = await _factory.CreateClient().GetAsync(path);

        Assert.True(resp.Headers.TryGetValues("X-Tamp-Findings-Version", out var values), $"no version header on {path}");
        Assert.Equal(BuildInfo.Current.Display, Assert.Single(values!));
    }

    [Fact]
    public async Task The_openapi_document_and_health_carry_the_same_version()
    {
        var client = _factory.CreateClient();

        var doc = await client.GetFromJsonAsync<JsonElement>("/openapi/v1.json");
        var health = await client.GetFromJsonAsync<JsonElement>("/health");

        Assert.Equal(BuildInfo.Current.Display, doc.GetProperty("info").GetProperty("version").GetString());
        Assert.Contains("/version", doc.GetProperty("info").GetProperty("description").GetString());
        Assert.Equal(BuildInfo.Current.Display, health.GetProperty("version").GetString());
        // The /version route documents its body, so generated clients can read it.
        var ok = doc.GetProperty("paths").GetProperty("/version").GetProperty("get").GetProperty("responses").GetProperty("200");
        Assert.True(ok.TryGetProperty("content", out _), "/version's 200 response should declare its schema");
    }
}
