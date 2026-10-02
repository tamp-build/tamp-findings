using System.Net;
using Microsoft.AspNetCore.Mvc.Testing;

namespace Tamp.Findings.Api.Tests;

// Sonar S5122: the API must not answer any origin. Browsers are not a client of it (the UI is same-origin
// Blazor Server; ingest, MCP and the CLI gate are not browsers), so CORS is closed unless an operator
// allows a specific origin through Cors:AllowedOrigins.
public class CorsPolicyTests : IClassFixture<TestApiFactory>
{
    private readonly TestApiFactory _factory;
    public CorsPolicyTests(TestApiFactory factory) => _factory = factory;

    private static async Task<HttpResponseMessage> GetWithOriginAsync(HttpClient client, string origin)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, "/health");
        req.Headers.Add("Origin", origin);
        return await client.SendAsync(req);
    }

    [Fact]
    public async Task By_default_no_origin_is_granted_access()
    {
        var client = _factory.CreateClient();

        var resp = await GetWithOriginAsync(client, "https://evil.example");

        Assert.False(resp.Headers.Contains("Access-Control-Allow-Origin"),
            "no Access-Control-Allow-Origin should be sent when no origin is configured");
    }

    [Fact]
    public async Task A_configured_origin_is_allowed_and_any_other_still_is_not()
    {
        var factory = _factory.WithWebHostBuilder(b => b.UseSetting("Cors:AllowedOrigins:0", "https://app.example"));
        var client = factory.CreateClient();

        var allowed = await GetWithOriginAsync(client, "https://app.example");
        var other = await GetWithOriginAsync(client, "https://evil.example");

        Assert.Equal("https://app.example", allowed.Headers.GetValues("Access-Control-Allow-Origin").Single());
        Assert.False(other.Headers.Contains("Access-Control-Allow-Origin"));
        Assert.NotEqual(HttpStatusCode.InternalServerError, allowed.StatusCode);
    }
}
