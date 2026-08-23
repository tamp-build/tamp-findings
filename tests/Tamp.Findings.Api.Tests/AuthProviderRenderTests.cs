namespace Tamp.Findings.Api.Tests;

// The Authentication panel and the provider sign-in routes (TFND-111).
public class AuthProviderRenderTests : IClassFixture<TestApiFactory>
{
    private readonly TestApiFactory _factory;

    public AuthProviderRenderTests(TestApiFactory factory) => _factory = factory;

    [Fact]
    public async Task The_panel_renders_rather_than_throwing()
    {
        var client = _factory.CreateSignedIn();

        var resp = await client.GetAsync("/system/authentication");

        resp.EnsureSuccessStatusCode();
    }

    [Fact]
    public async Task An_unreachable_database_never_renders_as_no_providers_configured()
    {
        // "No identity provider is configured" is a claim about whether anyone
        // can sign in, and this suite runs without Postgres.
        var client = _factory.CreateSignedIn();

        var body = await client.GetStringAsync("/system/authentication");

        Assert.Contains("Unavailable", body, StringComparison.Ordinal);
        Assert.DoesNotContain("No identity provider is configured", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_unknown_provider_scheme_lands_on_sign_in_rather_than_throwing()
    {
        // Challenging an unregistered scheme throws, and a 500 tells the
        // visitor nothing they can act on. A stale link or a provider somebody
        // just disabled is the common case.
        var client = _factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
        });

        var resp = await client.GetAsync("/auth/login/provider/does-not-exist");

        Assert.Equal(System.Net.HttpStatusCode.Redirect, resp.StatusCode);
        Assert.Contains("unknown_provider", resp.Headers.Location!.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_public_provider_list_reveals_names_and_schemes_only()
    {
        // It is anonymous by necessity — the sign-in page needs it before
        // anyone has signed in — so it must not become a reconnaissance gift.
        var client = _factory.CreateClient();

        var body = await client.GetStringAsync("/auth/providers");

        Assert.DoesNotContain("clientId", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("secret", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("authority", body, StringComparison.OrdinalIgnoreCase);
    }
}
