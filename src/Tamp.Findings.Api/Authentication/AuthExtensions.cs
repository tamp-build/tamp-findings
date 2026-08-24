using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
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
                    // Same handler as the OIDC path. This used to be an
                    // inline copy that redirected to "/" — written for the
                    // React SPA, whose SignInView read ?error= off the root.
                    // TFND-128 retired that SPA and the handler outlived it,
                    // so a refused GitHub sign-in landed on the application
                    // root instead of the sign-in page.
                    //
                    // It also collapsed everything except not_approved into
                    // "remote_failure", so a rejected setup token — the one
                    // case where the reader most needs to be told what
                    // happened, because they are holding the right token and
                    // being refused — arrived as a generic failure.
                    OnRemoteFailure = HandleRemoteFailure,
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

    // ------------------------------------------------------------------
    // Provider ticket handlers
    // ------------------------------------------------------------------
    //
    // Each of these does ONE thing: turn a provider's response into a
    // normalised Profile. Everything after that — the first-run admin claim,
    // the allowed-domain check, the MFA requirement, the approval gate, the
    // claims that go into the cookie — is ExternalSignIn's, because it is one
    // policy and two copies of it would eventually be two policies.

    /// <summary>
    /// GitHub's OAuth profile. Internal so the database-registered scheme
    /// (TFND-111) can reuse it rather than owning a second copy.
    /// </summary>
    internal static async Task HandleGitHubTicket(OAuthCreatingTicketContext ctx)
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

        // GitHub omits a private primary email from /user. The user:email scope
        // lets us pull it from /user/emails — pick the verified primary. Fall
        // through silently if the call fails; email is optional and the user is
        // already identified by their GitHub id.
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

        // The bootstrap login env var predates the registry and stays: it is
        // the recovery path for "the admin signed in before the variable was
        // set", and removing it would leave that instance unrecoverable.
        var bootstrapLogin = ctx.HttpContext.RequestServices.GetRequiredService<IConfiguration>()["GitHub:BootstrapAdminLogin"]
            ?? Environment.GetEnvironmentVariable("GITHUB_BOOTSTRAP_ADMIN_LOGIN");

        if (!string.IsNullOrWhiteSpace(bootstrapLogin)
            && string.Equals(bootstrapLogin, login, StringComparison.OrdinalIgnoreCase))
        {
            await PromoteBootstrapAsync(ctx.HttpContext, githubId, ctx.HttpContext.RequestAborted);
        }

        ctx.Properties.Items.TryGetValue(SetupTokenItem, out var presented);

        var outcome = await ExternalSignIn.ResolveAsync(
            ctx.HttpContext,
            new ExternalSignIn.Profile(
                ctx.Scheme.Name, githubId.ToString(), login, displayName, email, avatar,
                GitHubUserId: githubId,
                // GitHub OAuth asserts nothing about multi-factor. Reporting
                // otherwise would satisfy an MFA requirement that was never met
                // — which is why the registry refuses to let a GitHub provider
                // be marked as requiring one.
                MfaAsserted: false),
            presented,
            ctx.HttpContext.RequestAborted);

        if (!outcome.Ok)
        {
            ctx.Fail(outcome.Reason!);
            return;
        }

        ctx.Principal = outcome.Principal;
    }

    /// <summary>
    /// An OIDC token, already validated by the handler (TFND-111).
    ///
    /// Claim names vary between issuers, so each is read with a fallback chain
    /// rather than assuming one shape. An issuer that supplies none of them for
    /// a display name falls back to the subject, which is ugly and honest —
    /// better than a blank row.
    /// </summary>
    internal static async Task HandleOidcTicket(TokenValidatedContext ctx)
    {
        var claims = ctx.Principal ?? throw new InvalidOperationException("oidc principal missing");

        var subject = claims.FindFirst("sub")?.Value
            ?? claims.FindFirst(ClaimTypes.NameIdentifier)?.Value
            ?? throw new InvalidOperationException("oidc subject missing");

        var email = claims.FindFirst("email")?.Value ?? claims.FindFirst(ClaimTypes.Email)?.Value;

        var login = claims.FindFirst("preferred_username")?.Value
            ?? email
            ?? subject;

        var displayName = claims.FindFirst("name")?.Value
            ?? claims.FindFirst(ClaimTypes.Name)?.Value
            ?? login;

        // `amr` is the standard's own answer to "how did they authenticate".
        // Absent means the issuer did not say — which is NOT the same as "no
        // MFA happened", but it is the only thing this end can verify, and a
        // requirement satisfied by an absence would not be a requirement.
        var mfa = claims.FindAll("amr")
            .Any(c => c.Value is "mfa" or "otp" or "hwk" or "swk" or "sc" or "fpt" or "face" or "pin");

        // The setup token rides on the authentication properties, which are
        // null when the handler is invoked outside a challenge it started.
        string? presented = null;
        ctx.Properties?.Items.TryGetValue(SetupTokenItem, out presented);

        var outcome = await ExternalSignIn.ResolveAsync(
            ctx.HttpContext,
            new ExternalSignIn.Profile(
                ctx.Scheme.Name, subject, login, displayName, email,
                AvatarUrl: claims.FindFirst("picture")?.Value,
                GitHubUserId: null,
                MfaAsserted: mfa),
            presented,
            ctx.HttpContext.RequestAborted);

        if (!outcome.Ok)
        {
            ctx.Fail(outcome.Reason!);
            return;
        }

        ctx.Principal = outcome.Principal;
    }

    /// <summary>
    /// The bootstrap-login recovery path, kept from before the registry.
    ///
    /// Promotes an EXISTING row. It covers "the admin signed in before
    /// GITHUB_BOOTSTRAP_ADMIN_LOGIN was set", which is otherwise unrecoverable
    /// without database access — and it deliberately does not create a row,
    /// because creating one would consume the first-run condition that the
    /// setup token guards.
    /// </summary>
    private static async Task PromoteBootstrapAsync(HttpContext http, long githubId, CancellationToken ct)
    {
        var db = http.RequestServices.GetRequiredService<FindingsDbContext>();
        var user = await db.Users.FirstOrDefaultAsync(u => u.GitHubUserId == githubId, ct);
        if (user is null) return;

        if (user is { IsApproved: true, IsAdmin: true }) return;

        user.IsApproved = true;
        user.IsAdmin = true;
        await db.SaveChangesAsync(ct);
    }

    /// <summary>
    /// Land a failed round-trip back on the sign-in page with a reason it can
    /// render, rather than on a framework error page.
    /// </summary>
    internal static Task HandleRemoteFailure(RemoteFailureContext ctx)
    {
        ctx.Response.Redirect($"/signin?error={FailureReason(ctx.Failure)}");
        ctx.HandleResponse();
        return Task.CompletedTask;
    }

    /// <summary>
    /// Map a failure to a token the sign-in page knows how to explain.
    ///
    /// The known reasons pass through by name; everything else collapses to
    /// "remote_failure" rather than echoing an exception message into a query
    /// string, which is how internal detail ends up in a browser history and a
    /// proxy log.
    /// </summary>
    internal static string FailureReason(Exception? failure) => failure?.Message switch
    {
        "not_approved" => "not_approved",
        "setup_token" => "setup_token",
        "domain_not_allowed" => "domain_not_allowed",
        "mfa_required" => "mfa_required",
        _ => "remote_failure",
    };
}
