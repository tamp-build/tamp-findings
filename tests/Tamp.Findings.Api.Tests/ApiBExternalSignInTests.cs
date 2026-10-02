using System.Net;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Api.Authentication;
using Tamp.Findings.Application.Setup;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Api.Tests;

/// <summary>
/// The post-IdP sign-in policy (first-run seat claim, domain allow-list, MFA, approval) and the
/// provider ticket handlers, driven with synthetic profiles/contexts so no external IdP is needed.
/// Runs against its own database (TAMP_FINDINGS_TEST_DB + "_apibsignin") and resets it per test.
/// </summary>
[Collection("apib-signin")]
public sealed class ApiBExternalSignInTests : IAsyncLifetime
{
    private const string BootstrapLogin = "apib-boot";
    private static string? BaseConn => Environment.GetEnvironmentVariable("TAMP_FINDINGS_TEST_DB");

    private SignInFactory _factory = default!;
    private bool _available;

    public async Task InitializeAsync()
    {
        _available = !string.IsNullOrWhiteSpace(BaseConn);
        if (!_available) return;
        _factory = new SignInFactory(WithSuffix(BaseConn!, "_apibsignin"));
        _ = _factory.Services;   // boot + migrate now
        await ResetAsync();
    }

    public Task DisposeAsync() { _factory?.Dispose(); return Task.CompletedTask; }

    private static string WithSuffix(string conn, string suffix)
    {
        var b = new System.Data.Common.DbConnectionStringBuilder { ConnectionString = conn };
        var key = b.ContainsKey("Database") ? "Database" : "Db";
        b[key] = b[key] + suffix;
        return b.ConnectionString;
    }

    private sealed class SignInFactory(string conn) : WebApplicationFactory<Program>
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseSetting("ConnectionStrings:Findings", conn);
            builder.UseSetting("GitHub:BootstrapAdminLogin", BootstrapLogin);
        }
    }

    // ---- plumbing ---------------------------------------------------------------

    private SetupToken Setup => _factory.Services.GetRequiredService<SetupToken>();

    private async Task ResetAsync()
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<FindingsDbContext>();
        await db.Database.ExecuteSqlRawAsync("TRUNCATE TABLE \"Users\" CASCADE");
        await db.InstanceSettings.ExecuteDeleteAsync();
        await db.IdentityProviders.ExecuteDeleteAsync();
        Setup.Arm(0);
    }

    private static ExternalSignIn.Profile Gh(long id, string login, string? email = null, bool mfa = false) =>
        new("GitHub", id.ToString(), login, $"{login} display", email, "https://avatar.test/a.png", id, mfa);

    private static ExternalSignIn.Profile Oidc(string scheme, string sub, string login, string? email = null, bool mfa = false) =>
        new(scheme, sub, login, login, email, null, null, mfa);

    private async Task<SignInOutcome> ResolveAsync(ExternalSignIn.Profile profile, string? token = null)
    {
        using var scope = _factory.Services.CreateScope();
        var http = new DefaultHttpContext { RequestServices = scope.ServiceProvider };
        http.Connection.RemoteIpAddress = IPAddress.Parse("10.1.2.3");
        return await ExternalSignIn.ResolveAsync(http, profile, token, CancellationToken.None);
    }

    private async Task<T> WithDb<T>(Func<FindingsDbContext, Task<T>> f)
    {
        using var scope = _factory.Services.CreateScope();
        return await f(scope.ServiceProvider.GetRequiredService<FindingsDbContext>());
    }

    private Task Mutate(Func<FindingsDbContext, Task> f) => WithDb(async db => { await f(db); return 0; });

    private Task SetSettings(Action<InstanceSettings> change) => Mutate(async db =>
    {
        var s = await db.InstanceSettings.FirstOrDefaultAsync(x => x.Id == InstanceSettings.SingletonId);
        if (s is null) { s = new InstanceSettings(); db.InstanceSettings.Add(s); }
        change(s);
        await db.SaveChangesAsync();
    });

    private async Task<User> ClaimSeatAsync(long id = 1, string login = "founder")
    {
        var outcome = await ResolveAsync(Gh(id, login, $"{login}@corp.test"), Setup.ValueForStartupLog);
        Assert.True(outcome.Ok, outcome.Reason);
        return await WithDb(db => db.Users.SingleAsync(u => u.GitHubUserId == id));
    }

    // ---- first run ----------------------------------------------------------------

    [SkippableFact]
    public async Task First_run_without_the_right_setup_token_is_refused_and_creates_nothing()
    {
        Skip.IfNot(_available);

        var none = await ResolveAsync(Gh(10, "intruder"), token: null);
        var wrong = await ResolveAsync(Gh(10, "intruder"), token: "wrong");

        Assert.Equal("setup_token", none.Reason);
        Assert.Equal("setup_token", wrong.Reason);
        Assert.False(none.Ok);
        Assert.Equal(0, await WithDb(db => db.Users.CountAsync()));
        Assert.True(Setup.IsRequired);   // the seat is still claimable
    }

    [SkippableFact]
    public async Task First_run_with_the_token_claims_the_admin_seat_audits_it_and_disarms_the_token()
    {
        Skip.IfNot(_available);
        var token = Setup.ValueForStartupLog;

        var outcome = await ResolveAsync(Gh(11, "founder", "founder@corp.test"), token);

        Assert.True(outcome.Ok);
        var p = outcome.Principal!;
        Assert.Equal("founder", p.FindFirstValue(ClaimTypes.Name));
        Assert.Equal("True", p.FindFirstValue(AuthExtensions.TampIsAdminClaim));
        Assert.Equal("founder@corp.test", p.FindFirstValue(ClaimTypes.Email));
        var user = await WithDb(db => db.Users.SingleAsync(u => u.GitHubUserId == 11));
        Assert.True(user.IsAdmin && user.IsApproved);
        Assert.Equal(user.Id.ToString(), p.FindFirstValue(AuthExtensions.TampUserIdClaim));
        Assert.NotNull(user.LastLoginAt);

        Assert.False(Setup.IsRequired);
        Assert.False(Setup.Validate(token));
        var audit = await WithDb(db => db.AuditEntries.Where(a => a.SubjectId == user.Id).ToListAsync());
        var entry = Assert.Single(audit);
        Assert.Equal(AuditClass.Access, entry.Class);
        Assert.Contains("claimed the administrator seat", entry.Detail, StringComparison.Ordinal);
        Assert.Contains("10.1.2.3", entry.Detail, StringComparison.Ordinal);
    }

    // ---- ongoing registration -----------------------------------------------------

    [SkippableFact]
    public async Task A_second_user_registers_unapproved_is_refused_then_signs_in_once_approved()
    {
        Skip.IfNot(_available);
        await ClaimSeatAsync();

        var first = await ResolveAsync(Gh(20, "newcomer", "new@corp.test"));
        Assert.Equal("not_approved", first.Reason);
        var row = await WithDb(db => db.Users.SingleAsync(u => u.GitHubUserId == 20));
        Assert.False(row.IsApproved);
        Assert.False(row.IsAdmin);

        await Mutate(async db => { (await db.Users.SingleAsync(u => u.GitHubUserId == 20)).IsApproved = true; await db.SaveChangesAsync(); });

        var again = await ResolveAsync(Gh(20, "newcomer-renamed", null));
        Assert.True(again.Ok);
        Assert.Equal("False", again.Principal!.FindFirstValue(AuthExtensions.TampIsAdminClaim));
        var updated = await WithDb(db => db.Users.SingleAsync(u => u.GitHubUserId == 20));
        Assert.Equal("newcomer-renamed", updated.Login);
        Assert.Equal("new@corp.test", updated.Email);   // a missing email does not wipe the stored one
    }

    [SkippableFact]
    public async Task The_domain_allow_list_gates_registration_only()
    {
        Skip.IfNot(_available);
        await ClaimSeatAsync();
        await SetSettings(s => s.AllowedEmailDomains = ["corp.test"]);

        var outsider = await ResolveAsync(Gh(30, "outsider", "x@evil.test"));
        Assert.Equal("domain_not_allowed", outsider.Reason);
        Assert.Equal(0, await WithDb(db => db.Users.CountAsync(u => u.GitHubUserId == 30)));

        var noEmail = await ResolveAsync(Gh(31, "noemail", null));
        Assert.Equal("domain_not_allowed", noEmail.Reason);

        var insider = await ResolveAsync(Gh(32, "insider", "i@CORP.test"));
        Assert.Equal("not_approved", insider.Reason);   // allowed to register, still needs approval
        Assert.Equal(1, await WithDb(db => db.Users.CountAsync(u => u.GitHubUserId == 32)));

        // The founder already exists, so tightening the list does not lock them out.
        await SetSettings(s => s.AllowedEmailDomains = ["other.test"]);
        Assert.True((await ResolveAsync(Gh(1, "founder", "founder@corp.test"))).Ok);
    }

    [SkippableFact]
    public async Task A_role_that_requires_mfa_refuses_a_sign_in_that_did_not_assert_it()
    {
        Skip.IfNot(_available);
        var admin = await ClaimSeatAsync();
        await SetSettings(s => s.MfaRequiredRoles = ["Admin"]);

        var noMfa = await ResolveAsync(Gh(1, "founder", null, mfa: false));
        Assert.Equal("mfa_required", noMfa.Reason);
        Assert.True((await ResolveAsync(Gh(1, "founder", null, mfa: true))).Ok);

        // A project role in the required set counts too; an unrelated user is unaffected.
        var lead = new User { Login = "lead", DisplayName = "lead", GitHubUserId = 40, IsApproved = true };
        var plain = new User { Login = "plain", DisplayName = "plain", GitHubUserId = 41, IsApproved = true };
        Guid projectId = default;
        await Mutate(async db =>
        {
            var client = new Client { Name = "apib-signin-c-" + Guid.NewGuid().ToString("N") };
            var project = new Project { ClientId = client.Id, Name = "apib-signin-p-" + Guid.NewGuid().ToString("N") };
            db.Users.AddRange(lead, plain);
            db.Clients.Add(client);
            db.Projects.Add(project);
            db.ProjectRoleAssignments.Add(new ProjectRoleAssignment { UserId = lead.Id, Role = ProjectRole.LeadDev, ProjectId = project.Id });
            await db.SaveChangesAsync();
            projectId = project.Id;
        });
        Assert.NotEqual(Guid.Empty, projectId);
        await SetSettings(s => s.MfaRequiredRoles = ["leaddev"]);

        Assert.Equal("mfa_required", (await ResolveAsync(Gh(40, "lead"))).Reason);
        Assert.True((await ResolveAsync(Gh(41, "plain"))).Ok);
        Assert.True((await ResolveAsync(Gh(1, "founder"))).Ok);   // Admin no longer in the required set
        _ = admin;
    }

    [SkippableFact]
    public async Task Oidc_users_are_keyed_on_scheme_and_subject_and_the_provider_is_touched()
    {
        Skip.IfNot(_available);
        await ClaimSeatAsync();
        await Mutate(async db =>
        {
            db.IdentityProviders.Add(new IdentityProvider
            {
                Scheme = "entra", DisplayName = "Entra", ClientId = "cid", Kind = IdentityProviderKind.Oidc,
                Authority = "https://idp.test", CreatedByUserId = Guid.NewGuid(),
            });
            await db.SaveChangesAsync();
        });

        var created = await ResolveAsync(Oidc("entra", "sub-1", "oidc.user", "o@corp.test"));
        Assert.Equal("not_approved", created.Reason);
        var row = await WithDb(db => db.Users.SingleAsync(u => u.ExternalSubject == "sub-1"));
        Assert.Equal("entra", row.ExternalScheme);
        Assert.Null(row.GitHubUserId);

        await Mutate(async db => { (await db.Users.SingleAsync(u => u.ExternalSubject == "sub-1")).IsApproved = true; await db.SaveChangesAsync(); });
        var ok = await ResolveAsync(Oidc("entra", "sub-1", "oidc.user"));
        Assert.True(ok.Ok);
        Assert.Equal(row.Id.ToString(), ok.Principal!.FindFirstValue(AuthExtensions.TampUserIdClaim));
        Assert.Equal(1, await WithDb(db => db.Users.CountAsync(u => u.ExternalSubject == "sub-1")));
        Assert.NotNull((await WithDb(db => db.IdentityProviders.SingleAsync(p => p.Scheme == "entra"))).LastSignInAt);

        // Same subject under another scheme is a different identity.
        var other = await ResolveAsync(Oidc("okta", "sub-1", "oidc.user.okta"));
        Assert.Equal("not_approved", other.Reason);
        Assert.Equal(2, await WithDb(db => db.Users.CountAsync(u => u.ExternalSubject == "sub-1")));
    }

    // ---- GitHub ticket handler ----------------------------------------------------

    private sealed class FakeGitHub(string userJson, string? emailsJson) : HttpMessageHandler
    {
        public List<string> Calls { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var url = request.RequestUri!.ToString();
            Calls.Add(url);
            var body = url.EndsWith("/user/emails", StringComparison.Ordinal) ? emailsJson : userJson;
            return Task.FromResult(body is null
                ? new HttpResponseMessage(HttpStatusCode.Forbidden)
                : new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") });
        }
    }

    private async Task<(OAuthCreatingTicketContext ctx, FakeGitHub gh)> GitHubContext(
        string userJson, string? emailsJson, string? setupToken, IServiceScope scope)
    {
        var gh = new FakeGitHub(userJson, emailsJson);
        var http = new DefaultHttpContext { RequestServices = scope.ServiceProvider };
        var options = new OAuthOptions
        {
            ClientId = "id", ClientSecret = "secret", CallbackPath = "/cb",
            AuthorizationEndpoint = "https://github.test/authorize", TokenEndpoint = "https://github.test/token",
            UserInformationEndpoint = "https://api.github.test/user",
        };
        var props = new AuthenticationProperties();
        if (setupToken is not null) props.Items[AuthExtensions.SetupTokenItem] = setupToken;
        var tokens = OAuthTokenResponse.Success(JsonDocument.Parse("""{"access_token":"at-123","token_type":"bearer"}"""));
        var user = JsonDocument.Parse(userJson).RootElement.Clone();
        var ctx = new OAuthCreatingTicketContext(
            new ClaimsPrincipal(new ClaimsIdentity("GitHub")), props, http,
            new AuthenticationScheme("GitHub", "GitHub", typeof(OAuthHandler<OAuthOptions>)),
            options, new HttpClient(gh), tokens, user);
        await Task.CompletedTask;
        return (ctx, gh);
    }

    [SkippableFact]
    public async Task The_github_handler_claims_the_seat_via_the_setup_token_and_falls_back_to_the_emails_endpoint()
    {
        Skip.IfNot(_available);
        var token = Setup.ValueForStartupLog;
        using var scope = _factory.Services.CreateScope();
        var (ctx, gh) = await GitHubContext(
            """{"id":501,"login":"octo","name":"Octo Cat","email":null,"avatar_url":"https://a.test/o.png"}""",
            """[{"email":"secondary@x.test","primary":false,"verified":true},{"email":"primary@x.test","primary":true,"verified":true}]""",
            token, scope);

        await AuthExtensions.HandleGitHubTicket(ctx);

        Assert.Equal(2, gh.Calls.Count);
        Assert.NotNull(ctx.Principal);
        Assert.Equal("octo", ctx.Principal!.FindFirstValue(ClaimTypes.Name));
        Assert.Equal("primary@x.test", ctx.Principal.FindFirstValue(ClaimTypes.Email));
        var user = await WithDb(db => db.Users.SingleAsync(u => u.GitHubUserId == 501));
        Assert.Equal("Octo Cat", user.DisplayName);
        Assert.Equal("https://a.test/o.png", user.AvatarUrl);
        Assert.True(user.IsAdmin);
    }

    [SkippableFact]
    public async Task The_github_handler_survives_a_failing_emails_call_and_marks_a_refused_sign_in()
    {
        Skip.IfNot(_available);
        using var scope = _factory.Services.CreateScope();
        var (ctx, _) = await GitHubContext(
            """{"id":502,"login":"nameless","avatar_url":42}""", emailsJson: null, setupToken: "bad-token", scope);

        await AuthExtensions.HandleGitHubTicket(ctx);

        // Refused: the reason rides on the properties for HandleTicketReceived to act on.
        Assert.Equal("setup_token", ctx.Properties.Items["tamp.signin.refused"]);
        Assert.Equal(0, await WithDb(db => db.Users.CountAsync()));

        // And the last gate turns that into a redirect rather than a cookie.
        var ticket = new AuthenticationTicket(ctx.Principal!, ctx.Properties, "GitHub");
        var received = new TicketReceivedContext(
            new DefaultHttpContext(), new AuthenticationScheme("GitHub", null, typeof(OAuthHandler<OAuthOptions>)),
            new OAuthOptions { ClientId = "x", ClientSecret = "y", CallbackPath = "/cb", AuthorizationEndpoint = "https://a", TokenEndpoint = "https://t" },
            ticket);
        await AuthExtensions.HandleTicketReceived(received);
        Assert.True(received.Result?.Handled);
        Assert.Equal("/signin?error=setup_token", received.Response.Headers.Location.ToString());
    }

    [SkippableFact]
    public async Task The_bootstrap_login_promotes_an_existing_row_once_and_audits_it()
    {
        Skip.IfNot(_available);
        await ClaimSeatAsync();
        await Mutate(async db =>
        {
            db.Users.Add(new User { Login = BootstrapLogin, DisplayName = "boot", GitHubUserId = 600, IsApproved = false });
            await db.SaveChangesAsync();
        });

        for (var i = 0; i < 2; i++)
        {
            using var scope = _factory.Services.CreateScope();
            var (ctx, _) = await GitHubContext(
                $$"""{"id":600,"login":"{{BootstrapLogin}}","name":"Boot","email":"boot@x.test"}""", null, null, scope);
            await AuthExtensions.HandleGitHubTicket(ctx);
            Assert.NotNull(ctx.Principal);
            Assert.Equal("True", ctx.Principal!.FindFirstValue(AuthExtensions.TampIsAdminClaim));
        }

        var user = await WithDb(db => db.Users.SingleAsync(u => u.GitHubUserId == 600));
        Assert.True(user.IsAdmin && user.IsApproved);
        var promotions = await WithDb(db => db.AuditEntries
            .Where(a => a.SubjectId == user.Id && a.Detail!.Contains("GITHUB_BOOTSTRAP_ADMIN_LOGIN")).CountAsync());
        Assert.Equal(1, promotions);
    }

    // ---- OIDC ticket handler ------------------------------------------------------

    private TokenValidatedContext OidcContext(IServiceScope scope, IEnumerable<Claim> claims, AuthenticationProperties? props = null) =>
        new(new DefaultHttpContext { RequestServices = scope.ServiceProvider },
            new AuthenticationScheme("entra", "Entra", typeof(OpenIdConnectHandler)),
            new OpenIdConnectOptions(),
            new ClaimsPrincipal(new ClaimsIdentity(claims, "oidc")),
            props ?? new AuthenticationProperties());

    [SkippableFact]
    public async Task The_oidc_handler_maps_claims_with_fallbacks_and_reads_mfa_from_amr()
    {
        Skip.IfNot(_available);
        await ClaimSeatAsync();
        await SetSettings(s => s.MfaRequiredRoles = ["Admin"]);
        // An existing OIDC admin so the MFA requirement bites.
        await Mutate(async db =>
        {
            db.Users.Add(new User { Login = "oidc-admin", DisplayName = "oa", ExternalScheme = "entra", ExternalSubject = "adm", IsApproved = true, IsAdmin = true });
            await db.SaveChangesAsync();
        });

        using var scope = _factory.Services.CreateScope();

        var noMfa = OidcContext(scope, [new Claim("sub", "adm"), new Claim("preferred_username", "oidc-admin")]);
        await AuthExtensions.HandleOidcTicket(noMfa);
        Assert.Equal("mfa_required", noMfa.Properties!.Items["tamp.signin.refused"]);
        Assert.False(noMfa.Result?.Succeeded ?? false);

        var withMfa = OidcContext(scope, [new Claim("sub", "adm"), new Claim("amr", "pwd"), new Claim("amr", "otp")]);
        await AuthExtensions.HandleOidcTicket(withMfa);
        Assert.NotNull(withMfa.Principal);
        Assert.Equal("adm", withMfa.Principal!.FindFirstValue(ClaimTypes.Name));   // no login claim: the fallback chain lands on the subject

        // Subject-less principal is a malformed token.
        var bad = OidcContext(scope, [new Claim("email", "x@y.test")]);
        await Assert.ThrowsAsync<InvalidOperationException>(() => AuthExtensions.HandleOidcTicket(bad));

        // Name fallbacks: nothing but a subject -> subject is the login and display name.
        var minimal = OidcContext(scope, [new Claim(ClaimTypes.NameIdentifier, "only-sub")]);
        await AuthExtensions.HandleOidcTicket(minimal);
        var row = await WithDb(db => db.Users.SingleAsync(u => u.ExternalSubject == "only-sub"));
        Assert.Equal("only-sub", row.Login);
        Assert.Equal("only-sub", row.DisplayName);
        Assert.Equal("not_approved", minimal.Properties!.Items["tamp.signin.refused"]);

        // email is the next login fallback; ClaimTypes.Name the display fallback.
        var viaEmail = OidcContext(scope, [new Claim("sub", "s2"), new Claim(ClaimTypes.Email, "mail@x.test"), new Claim(ClaimTypes.Name, "Mail Person"), new Claim("picture", "https://p.test/p")]);
        await AuthExtensions.HandleOidcTicket(viaEmail);
        var row2 = await WithDb(db => db.Users.SingleAsync(u => u.ExternalSubject == "s2"));
        Assert.Equal("mail@x.test", row2.Login);
        Assert.Equal("Mail Person", row2.DisplayName);
    }

    // ---- ticket-received gate / failure mapping ------------------------------------

    private static TicketReceivedContext Received(ClaimsPrincipal? principal, AuthenticationProperties props) =>
        new(new DefaultHttpContext(), new AuthenticationScheme("x", null, typeof(OAuthHandler<OAuthOptions>)),
            new OAuthOptions { ClientId = "x", ClientSecret = "y", CallbackPath = "/cb", AuthorizationEndpoint = "https://a", TokenEndpoint = "https://t" },
            new AuthenticationTicket(principal ?? new ClaimsPrincipal(new ClaimsIdentity("x")), props, "x"));

    [Fact]
    public async Task Ticket_received_lets_an_identified_principal_through_and_stops_the_rest()
    {
        var identified = new ClaimsPrincipal(new ClaimsIdentity([new Claim(AuthExtensions.TampUserIdClaim, Guid.NewGuid().ToString())], "x"));
        var pass = Received(identified, new AuthenticationProperties());
        await AuthExtensions.HandleTicketReceived(pass);
        Assert.False(pass.Result?.Handled ?? false);

        var anon = Received(null, new AuthenticationProperties());
        await AuthExtensions.HandleTicketReceived(anon);
        Assert.True(anon.Result?.Handled);
        Assert.Equal("/signin?error=remote_failure", anon.Response.Headers.Location.ToString());

        // An explicit refusal wins even when the principal carries the claim.
        var refusedProps = new AuthenticationProperties();
        refusedProps.Items["tamp.signin.refused"] = "not_approved";
        var refused = Received(identified, refusedProps);
        await AuthExtensions.HandleTicketReceived(refused);
        Assert.Equal("/signin?error=not_approved", refused.Response.Headers.Location.ToString());
    }

    [Theory]
    [InlineData("not_approved", "not_approved")]
    [InlineData("setup_token", "setup_token")]
    [InlineData("domain_not_allowed", "domain_not_allowed")]
    [InlineData("mfa_required", "mfa_required")]
    [InlineData("secret internal detail", "remote_failure")]
    public void Failure_reasons_pass_through_by_name_and_everything_else_collapses(string message, string expected)
    {
        Assert.Equal(expected, AuthExtensions.FailureReason(new InvalidOperationException(message)));
        Assert.Equal("remote_failure", AuthExtensions.FailureReason(null));
    }

    [Fact]
    public async Task Remote_failure_redirects_to_the_sign_in_page_with_the_reason()
    {
        var ctx = new RemoteFailureContext(
            new DefaultHttpContext(), new AuthenticationScheme("x", null, typeof(OAuthHandler<OAuthOptions>)),
            new OAuthOptions { ClientId = "x", ClientSecret = "y", CallbackPath = "/cb", AuthorizationEndpoint = "https://a", TokenEndpoint = "https://t" },
            new InvalidOperationException("domain_not_allowed"));

        await AuthExtensions.HandleRemoteFailure(ctx);

        Assert.True(ctx.Result?.Handled);
        Assert.Equal("/signin?error=domain_not_allowed", ctx.Response.Headers.Location.ToString());
        _ = typeof(CookieAuthenticationDefaults);
    }
}

[CollectionDefinition("apib-signin")]
public sealed class ApiBSignInCollection;
