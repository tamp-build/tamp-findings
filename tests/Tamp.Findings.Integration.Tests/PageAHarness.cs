using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Integration.Tests;

/// <summary>Auth scheme issuing the app's own user-id claim for a seeded DB user.</summary>
public sealed class PageAAuthOptions : AuthenticationSchemeOptions
{
    public Guid UserId { get; set; }
    public string Login { get; set; } = "pagea";
}

public sealed class PageAAuthHandler : AuthenticationHandler<PageAAuthOptions>
{
    public const string SchemeName = "PageA";

    public PageAAuthHandler(IOptionsMonitor<PageAAuthOptions> options, ILoggerFactory logger, UrlEncoder encoder)
        : base(options, logger, encoder) { }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var identity = new ClaimsIdentity(
        [
            new Claim(ClaimTypes.Name, Options.Login),
            new Claim(ClaimTypes.NameIdentifier, Options.Login),
            new Claim("urn:tamp.findings:userId", Options.UserId.ToString()),
        ], SchemeName);
        return Task.FromResult(AuthenticateResult.Success(
            new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName)));
    }
}

/// <summary>Shared helpers for the PageA render tests (signed-in clients + a seeded world).</summary>
public static class PageAHarness
{
    public static HttpClient SignedInAs(this WebApplicationFactory<Program> factory, User user)
    {
        return factory.WithWebHostBuilder(b => b.ConfigureTestServices(services =>
        {
            services.AddAuthentication(PageAAuthHandler.SchemeName)
                .AddScheme<PageAAuthOptions, PageAAuthHandler>(PageAAuthHandler.SchemeName, o =>
                {
                    o.UserId = user.Id;
                    o.Login = user.Login;
                });
            services.PostConfigure<AuthenticationOptions>(o =>
            {
                o.DefaultAuthenticateScheme = PageAAuthHandler.SchemeName;
                o.DefaultChallengeScheme = PageAAuthHandler.SchemeName;
                o.DefaultScheme = PageAAuthHandler.SchemeName;
            });
        })).CreateClient();
    }

    public static string Suffix() => Guid.NewGuid().ToString("N")[..8];

    public static User NewUser(string s, bool admin) => new()
    {
        Login = $"pagea-{(admin ? "adm" : "usr")}-{s}",
        DisplayName = $"PageA {s}",
        Email = $"pagea{s}@e.test",
        IsApproved = true,
        IsAdmin = admin,
    };

    public static async Task<string> GetAsync(this HttpClient c, string url)
    {
        var resp = await c.GetAsync(url);
        var body = await resp.Content.ReadAsStringAsync();
        Assert.True(resp.IsSuccessStatusCode, $"{url} -> {(int)resp.StatusCode}: {body[..Math.Min(body.Length, 400)]}");
        return body;
    }
}
