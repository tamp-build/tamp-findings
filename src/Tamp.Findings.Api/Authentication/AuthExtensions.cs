using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Api.Authentication;

public static class AuthExtensions
{
    // Cookie scheme name. Default would also work; pinning a constant keeps
    // [Authorize(AuthenticationSchemes = ...)] readable.
    public const string CookieScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    public const string GitHubScheme = "GitHub";

    // Claim names for fields we stash on the principal beyond the standard
    // ClaimTypes set. Used by /auth/me and any future authorization handlers.
    public const string TampUserIdClaim = "urn:tamp.findings:userId";

    /// <summary>
    /// Key the setup token travels under in the authentication properties.
    ///
    /// It has to survive the OAuth round trip because with OAuth the visitor is
    /// already authenticated by the time the callback runs — asking for the
    /// token afterwards would mean either stashing an identity we have decided
    /// not to trust yet, or creating the very row we are trying not to create.
    /// </summary>
    public const string SetupTokenItem = "tamp.setupToken";
    public const string TampIsAdminClaim = "urn:tamp.findings:isAdmin";

    public static IServiceCollection AddTampFindingsAuth(this IServiceCollection services, IConfiguration config)
    {
        // Config layering:
        //   appsettings -> "GitHub:ClientId" etc.
        //   env var fallback -> GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET /
        //                       GITHUB_BOOTSTRAP_ADMIN_LOGIN
        // Reading the env vars explicitly so we can fail loud if the OAuth
        // app credentials are missing — silent empty strings produce a
        // useless "bad_verification_code" round-trip from GitHub.
        var clientId = config["GitHub:ClientId"]
            ?? Environment.GetEnvironmentVariable("GITHUB_CLIENT_ID")
            ?? "";
        var clientSecret = config["GitHub:ClientSecret"]
            ?? Environment.GetEnvironmentVariable("GITHUB_CLIENT_SECRET")
            ?? "";

        // Only register the GitHub OAuth handler if creds are actually
        // present. Without this guard, an empty ClientId triggers
        // OAuthOptions.Validate() to throw on EVERY request — even
        // /health, which is AllowAnonymous — because UseAuthentication
        // initializes all registered schemes per-request. Test hosts and
        // misconfigured deployments would 500 on every probe.
        //
        // Cookie scheme is always registered (login session storage
        // doesn't depend on which IdP is wired); only the GitHub
        // challenge endpoint becomes inactive without creds. The
        // /auth/login/github endpoint will return a clear 500
        // "scheme not registered" if hit, which is the right signal
        // for a misconfigured deployment.
        var hasGithubOAuth = !string.IsNullOrWhiteSpace(clientId) && !string.IsNullOrWhiteSpace(clientSecret);

        var authBuilder = services
            .AddAuthentication(o =>
            {
                // Both default to the cookie scheme so unauthenticated hits
                // to gated endpoints return 401 (via OnRedirectToLogin
                // below). GitHub is invoked only by the explicit challenge
                // in /auth/login/github — wiring it as the default would
                // bounce SPA fetches to github.com on expired cookies.
                o.DefaultScheme = CookieScheme;
                o.DefaultChallengeScheme = CookieScheme;
            })
            .AddCookie(CookieScheme, o =>
            {
                o.Cookie.Name = "tamp.findings.auth";
                o.Cookie.HttpOnly = true;
                o.Cookie.SameSite = SameSiteMode.Lax;
                o.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
                o.ExpireTimeSpan = TimeSpan.FromDays(7);
                o.SlidingExpiration = true;
                // SPA expects 401 from /auth/me when anon; without this the
                // cookie middleware would 302 to /Account/Login.
                o.Events.OnRedirectToLogin = ctx =>
                {
                    ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    return Task.CompletedTask;
                };
                o.Events.OnRedirectToAccessDenied = ctx =>
                {
                    ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
                    return Task.CompletedTask;
                };
            });

        if (hasGithubOAuth) authBuilder.AddOAuth(GitHubScheme, o =>
            {
                // Sign-in lands in the cookie scheme — the OAuth handler is
                // only used for the challenge round-trip, never as a session.
                o.SignInScheme = CookieScheme;
                o.ClientId = clientId;
                o.ClientSecret = clientSecret;
                o.CallbackPath = "/auth/github/callback";
                o.AuthorizationEndpoint = "https://github.com/login/oauth/authorize";
                o.TokenEndpoint = "https://github.com/login/oauth/access_token";
                o.UserInformationEndpoint = "https://api.github.com/user";
                o.Scope.Add("read:user");
                o.Scope.Add("user:email");
                o.SaveTokens = false;
                o.Events = new OAuthEvents
                {
                    OnCreatingTicket = HandleGitHubTicket,
                    OnRemoteFailure = ctx =>
                    {
                        // Land the user back on the SPA root with an error
                        // query param. SignInView reads ?error= and renders
                        // the appropriate message — keeps the user inside
                        // the SPA shell instead of bouncing to a standalone
                        // HTML page. /auth/denied stays as a no-SPA fallback.
                        var reason = ctx.Failure?.Message switch
                        {
                            "not_approved" => "not_approved",
                            _ => "remote_failure",
                        };
                        ctx.Response.Redirect($"/?error={reason}");
                        ctx.HandleResponse();
                        return Task.CompletedTask;
                    },
                };
            });

        services.AddAuthorization(o =>
        {
            // Default: every endpoint that doesn't explicitly opt out via
            // .AllowAnonymous() requires an approved, signed-in user. This
            // closes the gate on every SPA query route without having to
            // tag each one individually. /health, /version, /openapi, /auth,
            // and /ingest/* opt out (see Program.cs).
            o.FallbackPolicy = new Microsoft.AspNetCore.Authorization.AuthorizationPolicyBuilder()
                .RequireAuthenticatedUser()
                .Build();
        });

        return services;
    }

    // Looks up / upserts the User row from the GitHub profile response, then
    // either stashes the internal identity on the principal (approved) or
    // aborts with a Fail("not_approved") that OnRemoteFailure translates into
    // a /auth/denied redirect.
    private static async Task HandleGitHubTicket(OAuthCreatingTicketContext ctx)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, ctx.Options.UserInformationEndpoint);
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", ctx.AccessToken);
        req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        // GitHub rejects requests without a UA — its docs ask for the app name.
        req.Headers.UserAgent.ParseAdd("tamp.findings");
        using var resp = await ctx.Backchannel.SendAsync(req, ctx.HttpContext.RequestAborted);
        resp.EnsureSuccessStatusCode();

        using var stream = await resp.Content.ReadAsStreamAsync(ctx.HttpContext.RequestAborted);
        using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: ctx.HttpContext.RequestAborted);
        var root = doc.RootElement;

        var githubId = root.GetProperty("id").GetInt64();
        var login = root.GetProperty("login").GetString() ?? throw new InvalidOperationException("github login missing");
        var displayName = root.TryGetProperty("name", out var nameEl) && nameEl.ValueKind == JsonValueKind.String
            ? nameEl.GetString()! : login;
        var email = root.TryGetProperty("email", out var emailEl) && emailEl.ValueKind == JsonValueKind.String
            ? emailEl.GetString() : null;
        var avatar = root.TryGetProperty("avatar_url", out var avatarEl) && avatarEl.ValueKind == JsonValueKind.String
            ? avatarEl.GetString() : null;

        // GitHub omits a private primary email from /user. The user:email
        // scope lets us pull it from /user/emails — pick the verified
        // primary. Fall through silently if the call fails; email is
        // optional and the user is already identified by their GitHub id.
        if (string.IsNullOrEmpty(email))
        {
            using var emailReq = new HttpRequestMessage(HttpMethod.Get, "https://api.github.com/user/emails");
            emailReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", ctx.AccessToken);
            emailReq.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            emailReq.Headers.UserAgent.ParseAdd("tamp.findings");
            using var emailResp = await ctx.Backchannel.SendAsync(emailReq, ctx.HttpContext.RequestAborted);
            if (emailResp.IsSuccessStatusCode)
            {
                using var emailStream = await emailResp.Content.ReadAsStreamAsync(ctx.HttpContext.RequestAborted);
                using var emailDoc = await JsonDocument.ParseAsync(emailStream, cancellationToken: ctx.HttpContext.RequestAborted);
                foreach (var e in emailDoc.RootElement.EnumerateArray())
                {
                    var primary = e.TryGetProperty("primary", out var p) && p.GetBoolean();
                    var verified = e.TryGetProperty("verified", out var v) && v.GetBoolean();
                    if (primary && verified && e.TryGetProperty("email", out var addr) && addr.ValueKind == JsonValueKind.String)
                    {
                        email = addr.GetString();
                        break;
                    }
                }
            }
        }

        var db = ctx.HttpContext.RequestServices.GetRequiredService<FindingsDbContext>();
        var bootstrapLogin = ctx.HttpContext.RequestServices.GetRequiredService<IConfiguration>()["GitHub:BootstrapAdminLogin"]
            ?? Environment.GetEnvironmentVariable("GITHUB_BOOTSTRAP_ADMIN_LOGIN");
        var isBootstrap = !string.IsNullOrWhiteSpace(bootstrapLogin)
            && string.Equals(bootstrapLogin, login, StringComparison.OrdinalIgnoreCase);

        var user = await db.Users.FirstOrDefaultAsync(u => u.GitHubUserId == githubId, ctx.HttpContext.RequestAborted);

        // FIRST RUN: claiming the administrator seat (TFND-126).
        //
        // The bootstrap for the entire RBAC model. Without it a fresh
        // deployment has no admin, so nobody can approve anyone, grant a role
        // or create a client, and the only way in is editing the database by
        // hand.
        //
        // "First to sign in wins" would be simpler and has a race: between
        // deploying and the operator signing in, the instance is reachable
        // with an unclaimed admin seat. So the claim requires the setup token
        // printed to the container log at startup — possession of the log is
        // what proves you are the operator.
        //
        // The check is "no users at all", not "no admins": once anyone exists
        // the instance is in use, and promoting the next arrival would be
        // privilege escalation dressed as convenience.
        var setup = ctx.HttpContext.RequestServices
            .GetRequiredService<Tamp.Findings.Application.Setup.SetupToken>();

        var isUnclaimed = user is null
            && !await db.Users.AnyAsync(ctx.HttpContext.RequestAborted);

        if (isUnclaimed)
        {
            // Entered on the sign-in page and carried through the challenge,
            // so it is available here — BEFORE any row is written.
            ctx.Properties.Items.TryGetValue(SetupTokenItem, out var presented);

            if (!setup.Validate(presented))
            {
                // THE LOAD-BEARING BRANCH. Fail without creating anything.
                //
                // Writing a user row here — even an unapproved one — would
                // consume the "no users exist" condition and permanently break
                // the bootstrap, leaving an instance nobody can administer.
                // That is the difference between a setup token and a speed
                // bump, so this returns before the upsert rather than after.
                ctx.HttpContext.RequestServices
                    .GetRequiredService<ILoggerFactory>()
                    .CreateLogger("Tamp.Findings.Setup")
                    .LogWarning(
                        "Rejected an admin claim for {Login}: setup token missing or wrong. No account created.",
                        login);
                ctx.Fail("setup_token");
                return;
            }
        }

        var isFirstUser = isUnclaimed;

        if (user is null)
        {
            user = new User
            {
                Login = login,
                DisplayName = displayName,
                Email = email,
                GitHubUserId = githubId,
                AvatarUrl = avatar,
                IsApproved = isBootstrap || isFirstUser,
                IsAdmin = isBootstrap || isFirstUser,
            };
            db.Users.Add(user);
        }
        else
        {
            user.Login = login;
            user.DisplayName = displayName;
            user.Email = email ?? user.Email;
            user.AvatarUrl = avatar ?? user.AvatarUrl;
            // Bootstrap login promotes an existing row too — covers the
            // "admin signed in before GITHUB_BOOTSTRAP_ADMIN_LOGIN was set"
            // recovery case.
            if (isBootstrap)
            {
                user.IsApproved = true;
                user.IsAdmin = true;
            }
        }
        user.LastLoginAt = DateTimeOffset.UtcNow;
        await db.SaveChangesAsync(ctx.HttpContext.RequestAborted);

        // The seat is claimed. Disarm immediately so the token stops working
        // and stops being printed on the next restart — a claim token that
        // outlives the claim is just a standing credential.
        if (isFirstUser) setup.Claim();

        if (!user.IsApproved)
        {
            ctx.Fail("not_approved");
            return;
        }

        // Wipe the placeholder identity the OAuth handler built and replace
        // it with one we control — keeps the cookie minimal (no GH access
        // token, no scattered urn:github:* claims).
        var identity = new ClaimsIdentity(ctx.Scheme.Name);
        identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()));
        identity.AddClaim(new Claim(ClaimTypes.Name, user.Login));
        identity.AddClaim(new Claim(TampUserIdClaim, user.Id.ToString()));
        identity.AddClaim(new Claim(TampIsAdminClaim, user.IsAdmin.ToString()));
        if (!string.IsNullOrEmpty(user.Email))
            identity.AddClaim(new Claim(ClaimTypes.Email, user.Email));
        ctx.Principal = new ClaimsPrincipal(identity);
    }
}
