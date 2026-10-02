using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Tamp.Findings.Api.Authentication;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.SystemAdmin;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Integration.Tests;

/// <summary>
/// Scheme registration (static GitHub + database-registered providers), the cookie scheme's
/// API-friendly events, and the /auth endpoints. No external IdP is contacted: challenges are only
/// followed as far as the redirect to the provider.
/// </summary>
[Collection(DatabaseCollection.Name)]
public class ApiBAuthTests
{
    private readonly DatabaseFixture _fx;
    public ApiBAuthTests(DatabaseFixture fx) => _fx = fx;

    private WebApplicationFactory<Program> WithGitHub() =>
        _fx.Factory!.WithWebHostBuilder(b =>
        {
            b.UseSetting("GitHub:ClientId", "apib-client-id");
            b.UseSetting("GitHub:ClientSecret", "apib-client-secret");
        });

    private static HttpClient NoRedirect(WebApplicationFactory<Program> f) =>
        f.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

    private static Principal Admin() => Principal.For(Guid.NewGuid(), "apib-admin", true, []);

    // ---- static registration -------------------------------------------------

    [SkippableFact]
    public async Task Github_scheme_registers_only_when_credentials_are_configured()
    {
        Skip.IfNot(_fx.Available);
        var configured = WithGitHub();

        var schemes = configured.Services.GetRequiredService<IAuthenticationSchemeProvider>();
        Assert.NotNull(await schemes.GetSchemeAsync(AuthExtensions.GitHubScheme));
        Assert.NotNull(await schemes.GetSchemeAsync(AuthExtensions.CookieScheme));

        var oauth = configured.Services.GetRequiredService<IOptionsMonitor<OAuthOptions>>().Get(AuthExtensions.GitHubScheme);
        Assert.Equal("apib-client-id", oauth.ClientId);
        Assert.Equal("/auth/github/callback", oauth.CallbackPath.Value);
        Assert.Contains("read:user", oauth.Scope);
        Assert.Equal(AuthExtensions.CookieScheme, oauth.SignInScheme);
        Assert.False(oauth.SaveTokens);
    }

    [SkippableFact]
    public void Cookie_events_answer_with_status_codes_rather_than_redirects()
    {
        Skip.IfNot(_fx.Available);
        var cookie = _fx.Factory!.Services.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>()
            .Get(AuthExtensions.CookieScheme);
        Assert.Equal("tamp.findings.auth", cookie.Cookie.Name);
        Assert.True(cookie.Cookie.HttpOnly);

        var scheme = new AuthenticationScheme(AuthExtensions.CookieScheme, null, typeof(CookieAuthenticationHandler));

        var loginCtx = new RedirectContext<CookieAuthenticationOptions>(
            new DefaultHttpContext(), scheme, cookie, new AuthenticationProperties(), "/login");
        cookie.Events.OnRedirectToLogin(loginCtx);
        Assert.Equal(StatusCodes.Status401Unauthorized, loginCtx.HttpContext.Response.StatusCode);

        var deniedCtx = new RedirectContext<CookieAuthenticationOptions>(
            new DefaultHttpContext(), scheme, cookie, new AuthenticationProperties(), "/denied");
        cookie.Events.OnRedirectToAccessDenied(deniedCtx);
        Assert.Equal(StatusCodes.Status403Forbidden, deniedCtx.HttpContext.Response.StatusCode);
    }

    [SkippableFact]
    public async Task An_anonymous_api_call_is_401_not_a_redirect()
    {
        Skip.IfNot(_fx.Available);
        var resp = await NoRedirect(_fx.Factory!).GetAsync("/findings/dast-tree");
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    // ---- /auth endpoints ------------------------------------------------------

    [SkippableFact]
    public async Task Login_github_challenges_with_a_safe_return_url()
    {
        Skip.IfNot(_fx.Available);
        var http = NoRedirect(WithGitHub());

        var resp = await http.GetAsync("/auth/login/github?returnUrl=/projects&setupToken=tok");

        Assert.Equal(HttpStatusCode.Redirect, resp.StatusCode);
        var location = resp.Headers.Location!.ToString();
        Assert.StartsWith("https://github.com/login/oauth/authorize", location, StringComparison.Ordinal);
        Assert.Contains("client_id=apib-client-id", location, StringComparison.Ordinal);

        // An absolute returnUrl is replaced by "/" — still a plain challenge.
        var evil = await http.GetAsync("/auth/login/github?returnUrl=https://evil.test/");
        Assert.Equal(HttpStatusCode.Redirect, evil.StatusCode);
    }

    [SkippableFact]
    public async Task Login_provider_redirects_unknown_schemes_and_challenges_known_ones()
    {
        Skip.IfNot(_fx.Available);
        var factory = WithGitHub();
        var http = NoRedirect(factory);

        var unknown = await http.GetAsync("/auth/login/provider/nope-nope");
        Assert.Equal(HttpStatusCode.Redirect, unknown.StatusCode);
        Assert.Contains("unknown_provider", unknown.Headers.Location!.ToString(), StringComparison.Ordinal);

        var known = await http.GetAsync($"/auth/login/provider/{AuthExtensions.GitHubScheme}?returnUrl=/x&setupToken=abc");
        Assert.Equal(HttpStatusCode.Redirect, known.StatusCode);
        Assert.StartsWith("https://github.com/login/oauth/authorize", known.Headers.Location!.ToString(), StringComparison.Ordinal);
    }

    [SkippableFact]
    public async Task Me_reflects_the_database_row_and_drops_unapproved_users()
    {
        Skip.IfNot(_fx.Available);
        var s = ApiBSupport.Suffix();
        ApiBSupport.World w;
        Guid pendingId;
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            w = await ApiBSupport.SeedWorldAsync(db, s);
            var pending = new User { Login = $"apib-pending-{s}", DisplayName = "p", IsApproved = false };
            db.Users.Add(pending);
            await db.SaveChangesAsync();
            pendingId = pending.Id;
        }
        var authed = _fx.Factory!.WithTestAuth();

        Assert.Equal(HttpStatusCode.Unauthorized, (await authed.As(null).GetAsync("/auth/me")).StatusCode);

        var ok = await authed.As(w.AdminId).GetAsync("/auth/me");
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        var me = JsonDocument.Parse(await ok.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal(w.AdminLogin, me.GetProperty("login").GetString());
        Assert.True(me.GetProperty("isAdmin").GetBoolean());

        // Unapproved: treated as signed out. Deleted: same.
        Assert.Equal(HttpStatusCode.Unauthorized, (await authed.As(pendingId).GetAsync("/auth/me")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await authed.As(Guid.NewGuid()).GetAsync("/auth/me")).StatusCode);
    }

    [SkippableFact]
    public async Task Logout_is_anonymous_and_denied_page_explains_the_reason()
    {
        Skip.IfNot(_fx.Available);
        var http = _fx.Factory!.CreateClient();

        var logout = await http.PostAsync("/auth/logout", null);
        Assert.Equal(HttpStatusCode.NoContent, logout.StatusCode);

        var notApproved = await http.GetStringAsync("/auth/denied?reason=not_approved");
        Assert.Contains("allowlist", notApproved, StringComparison.Ordinal);
        var generic = await http.GetStringAsync("/auth/denied?reason=<script>");
        Assert.Contains("Sign-in failed", generic, StringComparison.Ordinal);
        Assert.DoesNotContain("<script>", generic, StringComparison.Ordinal);
    }

    // ---- database-registered providers ----------------------------------------

    [SkippableFact]
    public async Task Database_providers_register_configure_list_and_disappear_when_disabled()
    {
        Skip.IfNot(_fx.Available);
        var s = ApiBSupport.Suffix();
        var ghScheme = $"apibgh{s}";
        var oidcScheme = $"apiboidc{s}";
        var logs = new ApiBLogCapture();
        var host = _fx.Factory!.WithWebHostBuilder(b => b.ConfigureTestServices(sv => sv.AddSingleton<ILoggerProvider>(logs)));
        var http = NoRedirect(host);

        try
        {
            using (var scope = _fx.Scope())
            {
                var svc = scope.ServiceProvider.GetRequiredService<IdentityProviderService>();
                var gh = await svc.SaveAsync(Admin(), null, new ProviderDraft(
                    IdentityProviderKind.GitHubOAuth, ghScheme, "Apib GitHub", "gh-id", "gh-secret", null, null, true, false));
                Assert.True(gh.Success, gh.Error);
                var oidc = await svc.SaveAsync(Admin(), null, new ProviderDraft(
                    IdentityProviderKind.Oidc, oidcScheme, "Apib OIDC", "oidc-id", "oidc-secret",
                    "https://idp.example.test", "groups", true, true));
                Assert.True(oidc.Success, oidc.Error);
                // A scheme that collides with a static one is skipped, not fatal.
                var clash = await svc.SaveAsync(Admin(), null, new ProviderDraft(
                    IdentityProviderKind.GitHubOAuth, AuthExtensions.CookieScheme, "Clash", "c-id", "c-secret", null, null, true, false));
                Assert.True(clash.Success, clash.Error);
            }

            var registry = host.Services.GetRequiredService<DynamicSchemeRegistry>();
            await registry.RebuildAsync();
            await registry.RebuildAsync();   // idempotent

            var schemes = host.Services.GetRequiredService<IAuthenticationSchemeProvider>();
            Assert.NotNull(await schemes.GetSchemeAsync(ghScheme));
            Assert.NotNull(await schemes.GetSchemeAsync(oidcScheme));
            Assert.Equal("Apib GitHub", (await schemes.GetSchemeAsync(ghScheme))!.DisplayName);

            var oauth = host.Services.GetRequiredService<IOptionsMonitor<OAuthOptions>>().Get(ghScheme);
            Assert.Equal("gh-id", oauth.ClientId);
            Assert.Equal("gh-secret", oauth.ClientSecret);
            Assert.Equal($"/auth/{ghScheme}/callback", oauth.CallbackPath.Value);
            Assert.Contains("user:email", oauth.Scope);   // default scopes when none supplied

            var oidcOpts = host.Services.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>().Get(oidcScheme);
            Assert.Equal("https://idp.example.test", oidcOpts.Authority);
            Assert.Equal("code", oidcOpts.ResponseType);
            Assert.True(oidcOpts.UsePkce);
            Assert.Contains("groups", oidcOpts.Scope);
            Assert.Contains("openid", oidcOpts.Scope);
            Assert.Equal($"/auth/{oidcScheme}/callback", oidcOpts.CallbackPath.Value);

            // A DB provider's options are never applied to an unrelated name, or to the wrong kind.
            var unrelated = host.Services.GetRequiredService<IOptionsMonitor<OAuthOptions>>().Get(oidcScheme);
            Assert.Null(unrelated.ClientId);

            // The anonymous provider list shows names and schemes only.
            var list = await http.GetStringAsync("/auth/providers");
            Assert.Contains(ghScheme, list, StringComparison.Ordinal);
            Assert.DoesNotContain("gh-secret", list, StringComparison.Ordinal);
            Assert.DoesNotContain("gh-id", list, StringComparison.Ordinal);

            // Challenge a DB-registered OAuth scheme end to end as far as the redirect.
            var challenge = await http.GetAsync($"/auth/login/provider/{ghScheme}");
            Assert.True(challenge.StatusCode == HttpStatusCode.Redirect, string.Join(" | ", logs.Lines));
            Assert.Contains("client_id=gh-id", challenge.Headers.Location!.ToString(), StringComparison.Ordinal);

            // Event wiring on the DB schemes.
            Assert.NotNull(oauth.Events);
            Assert.NotNull(oidcOpts.Events.OnTokenValidated);
            Assert.NotNull(oidcOpts.Events.OnTicketReceived);
            var failure = new RemoteFailureContext(
                new DefaultHttpContext(), new AuthenticationScheme(oidcScheme, null, typeof(OpenIdConnectHandler)),
                oidcOpts, new InvalidOperationException("mfa_required"));
            await oidcOpts.Events.OnRemoteFailure(failure);
            Assert.Equal("/signin?error=mfa_required", failure.HttpContext.Response.Headers.Location.ToString());
        }
        finally
        {
            using var scope = _fx.Scope();
            var db = _fx.Db(scope);
            await db.IdentityProviders.Where(p => p.Scheme == ghScheme || p.Scheme == oidcScheme || p.Scheme == AuthExtensions.CookieScheme)
                .ExecuteDeleteAsync();
            await host.Services.GetRequiredService<DynamicSchemeRegistry>().RebuildAsync();
        }

        var after = host.Services.GetRequiredService<IAuthenticationSchemeProvider>();
        Assert.Null(await after.GetSchemeAsync(ghScheme));
        Assert.Null(await after.GetSchemeAsync(oidcScheme));
        Assert.NotNull(await after.GetSchemeAsync(AuthExtensions.CookieScheme));
    }
}
