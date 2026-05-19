using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Hosting;

namespace Tamp.Findings.Api.Tests;

public class HealthEndpointTests : IClassFixture<TestApiFactory>
{
    private readonly TestApiFactory _factory;

    public HealthEndpointTests(TestApiFactory factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task GET_health_returns_ok()
    {
        var client = _factory.CreateClient();
        var resp = await client.GetAsync("/health");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var body = await resp.Content.ReadFromJsonAsync<HealthResponse>();
        Assert.Equal("ok", body!.Status);
        Assert.Equal("tamp.findings.api", body.Service);
    }

    private sealed record HealthResponse(string Status, string Service);
}

// Test host without the migrate-on-startup hook — there is no Postgres in
// the test process, and /health does not touch the DB.
public sealed class TestApiFactory : WebApplicationFactory<Program>
{
    protected override IHost CreateHost(IHostBuilder builder)
    {
        Environment.SetEnvironmentVariable("TAMP_FINDINGS_SKIP_MIGRATE", "true");
        return base.CreateHost(builder);
    }
}
