using System.Net;

namespace Tamp.Findings.Api.Tests;

// The dev-only Claude Design access endpoint (TFND-167) is OFF by default.
//
// It is an auth bypass, so the one property that must never regress is that it
// does not exist unless explicitly enabled by env var — and that a wrong token
// is indistinguishable from no route. Enabling + the happy path are verified
// live against the lab, not here (this suite runs DB-less and without the env).
public class DesignAccessTests : IClassFixture<TestApiFactory>
{
    private readonly TestApiFactory _factory;

    public DesignAccessTests(TestApiFactory factory) => _factory = factory;

    [Fact]
    public async Task Design_access_is_404_when_not_configured()
    {
        var client = _factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
        });

        var resp = await client.GetAsync("/auth/design?t=anything&r=/");

        // Disabled (no env) ⇒ the route 404s rather than authenticating anyone.
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }
}
