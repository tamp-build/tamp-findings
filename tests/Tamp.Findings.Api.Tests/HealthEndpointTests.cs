using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.TestHost;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using System.Xml.Linq;
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

    [Fact]
    public async Task Liveness_stays_ok_with_the_database_unreachable()
    {
        // THE point of having two probes. This fixture points at a closed port,
        // so the database genuinely is down — and liveness must still say ok.
        // A failing liveness probe restarts the container, and restarting an
        // application because Postgres is down turns an outage into a crash
        // loop that recovers more slowly and destroys the logs explaining it.
        var client = _factory.CreateClient();

        var resp = await client.GetAsync("/health");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task Readiness_is_503_with_the_database_unreachable()
    {
        // Readiness says "not now" so an orchestrator pulls this instance out
        // of the load balancer rather than sending it traffic that will 500.
        var client = _factory.CreateClient();

        var resp = await client.GetAsync("/ready");

        Assert.Equal(HttpStatusCode.ServiceUnavailable, resp.StatusCode);
    }

    [Fact]
    public async Task Readiness_says_why_rather_than_returning_a_bare_503()
    {
        // A bare 503 from a readiness probe is the least actionable thing an
        // operator can be handed at three in the morning.
        var client = _factory.CreateClient();

        var resp = await client.GetAsync("/ready");
        var body = await resp.Content.ReadAsStringAsync();

        Assert.Contains("not-ready", body, StringComparison.Ordinal);
        Assert.Contains("reason", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Readiness_does_not_leak_the_connection_string()
    {
        // A connection-string exception message carries a host and a username,
        // and this endpoint is anonymous.
        var client = _factory.CreateClient();

        var body = await (await client.GetAsync("/ready")).Content.ReadAsStringAsync();

        Assert.DoesNotContain("Password", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Username", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("127.0.0.1", body, StringComparison.Ordinal);
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

        // A configured identity provider, because every real deployment has
        // one and the sign-in page now renders from the set that exists rather
        // than from a hardcoded button. Without this the host offers no way in
        // at all, and tests about the sign-in page would be asserting against
        // a misconfiguration rather than against the page.
        //
        // The values are never exchanged with GitHub — no test completes an
        // OAuth round-trip. They exist so the scheme registers, which is the
        // condition the page actually reads.
        Environment.SetEnvironmentVariable("GITHUB_CLIENT_ID", "test-client-id");
        Environment.SetEnvironmentVariable("GITHUB_CLIENT_SECRET", "test-client-secret");

        return base.CreateHost(builder);
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder) =>
        // The host keeps its data-protection keys in the database (TFND-137),
        // and this factory points at a database that is not there — on purpose,
        // so rendering can be tested without Postgres.
        //
        // Left alone, every page that renders antiforgery state 500s while
        // reaching for a key ring it cannot load, and roughly a hundred tests
        // fail for a reason that has nothing to do with what they assert.
        //
        // So the tests get a ring in memory. Registered through
        // ConfigureTestServices, which runs after the application's own
        // registrations and therefore wins. Production is untouched, and
        // HostDataProtectionTests covers the real configuration directly rather
        // than through this host.
        builder.ConfigureTestServices(services =>
            services.AddOptions<KeyManagementOptions>()
                .Configure(o => o.XmlRepository = new InMemoryXmlRepository()));

    /// <summary>A key ring that lives and dies with the test host.</summary>
    private sealed class InMemoryXmlRepository : IXmlRepository
    {
        private readonly List<XElement> _elements = [];

        public IReadOnlyCollection<XElement> GetAllElements()
        {
            lock (_elements) return _elements.ToArray();
        }

        public void StoreElement(XElement element, string friendlyName)
        {
            lock (_elements) _elements.Add(element);
        }
    }
}
