using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Tamp.Findings.Api.Tests;

/// <summary>
/// A signed-in HTTP client for tests.
///
/// Screens carry <c>[Authorize]</c>, so an anonymous request renders the
/// NotAuthorized fragment and every page looks identical. That makes most
/// screen assertions vacuous — you cannot tell an attestation from an explorer
/// spine if neither renders. This handler supplies a principal so the page
/// body actually renders and tests can assert on it.
///
/// It replaces AUTHENTICATION only. Authorization still runs normally, which
/// is the point: TFND-68's capability matrix has to be exercised, not bypassed.
/// </summary>
public static class AuthenticatedClient
{
    public const string Scheme = "Test";

    public static HttpClient CreateSignedIn(
        this WebApplicationFactory<Program> factory,
        string login = "test-user",
        bool isAdmin = false)
    {
        return factory
            .WithWebHostBuilder(b => b.ConfigureTestServices(services =>
            {
                services.AddAuthentication(Scheme)
                    .AddScheme<TestAuthOptions, TestAuthHandler>(Scheme, o =>
                    {
                        o.Login = login;
                        o.IsAdmin = isAdmin;
                    });

                // The app's own default is the cookie scheme; point the
                // defaults at the test scheme so [Authorize] resolves against
                // it without every test naming a scheme.
                services.PostConfigure<AuthenticationOptions>(o =>
                {
                    o.DefaultAuthenticateScheme = Scheme;
                    o.DefaultChallengeScheme = Scheme;
                    o.DefaultScheme = Scheme;
                });
            }))
            .CreateClient();
    }
}

public sealed class TestAuthOptions : AuthenticationSchemeOptions
{
    public string Login { get; set; } = "test-user";
    public bool IsAdmin { get; set; }
}

public sealed class TestAuthHandler : AuthenticationHandler<TestAuthOptions>
{
    public TestAuthHandler(IOptionsMonitor<TestAuthOptions> options, ILoggerFactory logger, UrlEncoder encoder)
        : base(options, logger, encoder) { }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var identity = new ClaimsIdentity(
        [
            new Claim(ClaimTypes.Name, Options.Login),
            new Claim(ClaimTypes.NameIdentifier, Options.Login),
        ], AuthenticatedClient.Scheme);

        var ticket = new AuthenticationTicket(new ClaimsPrincipal(identity), AuthenticatedClient.Scheme);
        return Task.FromResult(AuthenticateResult.Success(ticket));
    }
}
