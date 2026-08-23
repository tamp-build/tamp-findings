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

/// <summary>
/// Test host with NO database, deliberately and deterministically.
///
/// The app defaults to Host=localhost;Port=5544, which is also where a
/// developer's dev container listens — so this suite was silently connecting
/// to whatever happened to be running, and tests asserting the
/// database-unavailable behaviour passed or failed depending on whether a
/// container was up. Pointing at a closed port makes "no database" a fact
/// rather than a coincidence.
///
/// Tests that DO need a database live in Tamp.Findings.Integration.Tests,
/// which takes its connection string from TAMP_FINDINGS_TEST_DB and skips
/// when that is unset.
/// </summary>
public sealed class TestApiFactory : WebApplicationFactory<Program>
{
    /// <summary>Port 1 is reserved and never listening. Fails fast rather than hanging.</summary>
    private const string UnreachableDatabase =
        "Host=127.0.0.1;Port=1;Database=none;Username=none;Password=none;Timeout=1;Command Timeout=1";

    protected override IHost CreateHost(IHostBuilder builder)
    {
        Environment.SetEnvironmentVariable("TAMP_FINDINGS_SKIP_MIGRATE", "true");
        Environment.SetEnvironmentVariable("TAMP_FINDINGS_DB", UnreachableDatabase);
        return base.CreateHost(builder);
    }
}
