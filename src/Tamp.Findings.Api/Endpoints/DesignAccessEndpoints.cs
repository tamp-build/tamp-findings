using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Api.Authentication;
using Tamp.Findings.Application.Auditing;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Api.Endpoints;

// ─────────────────────────────────────────────────────────────────────────────
//  TEMPORARY — DEVELOPMENT ONLY.  REMOVE BEFORE THIS MATTERS. (TFND-167)
//
//  Pure-URL access for Claude Design (Claude Desktop) — a cloud fetcher that
//  reaches a URL once, statelessly, with no interaction on our end. Two ways in:
//
//   1. /auth/design?t=<token>&r=<local-path>  — mints the normal auth cookie
//      then 302s to <local-path>. Works for a client that follows redirects AND
//      keeps the cookie across the hop (a real browser).
//
//   2. ANY page + ?__design=<token>  (e.g. /portfolio?__design=<token>) —
//      authenticates that ONE request inline, before authorization runs, with
//      NO cookie and NO redirect. This is what a stateless single-GET renderer
//      needs: the prerendered HTML comes back authenticated in one response.
//      (It also mints the cookie as a courtesy, so a cookie-capable client stays
//      signed in for follow-up requests.)
//
//  This is an auth BYPASS on a security product. It is acceptable ONLY because:
//    * it is OFF unless BOTH env vars below are set (absent ⇒ neither path does
//      anything — the route 404s and the query param is ignored), so it cannot
//      be on by accident;
//    * the token is a configured secret — rotate or kill it by changing the env;
//    * every mint is audited, and the query param authenticates a single request.
//
//  Removal = unset the env vars and delete this file + its MapDesignAccess /
//  UseDesignTokenAuth calls in Program.cs.
// ─────────────────────────────────────────────────────────────────────────────
public static class DesignAccessEndpoints
{
    public const string TokenVar = "TAMP_FINDINGS_DESIGN_TOKEN";
    public const string LoginVar = "TAMP_FINDINGS_DESIGN_LOGIN";

    // The query parameter that carries the token for inline, cookie-free auth.
    public const string QueryParam = "__design";

    public static bool Enabled =>
        !string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(TokenVar))
        && !string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(LoginVar));

    public static IEndpointRouteBuilder MapDesignAccess(this IEndpointRouteBuilder app)
    {
        // t = the shared secret; r = a LOCAL return path to land on.
        // Anonymous by construction — its whole job is to establish auth from a
        // token, so it must run before the global authenticated-user policy.
        app.MapGet("/auth/design", async (
            HttpContext ctx, FindingsDbContext db, AuditLog audit,
            string? t, string? r, CancellationToken ct) =>
        {
            var secret = Environment.GetEnvironmentVariable(TokenVar);
            var login = Environment.GetEnvironmentVariable(LoginVar);

            // Disabled, or wrong/absent token → 404. Never confirm the route
            // exists to a caller that cannot present the secret.
            if (string.IsNullOrWhiteSpace(secret) || string.IsNullOrWhiteSpace(login)) return Results.NotFound();
            if (string.IsNullOrEmpty(t) || !FixedTimeEquals(t, secret)) return Results.NotFound();

            var principal = await BuildPrincipalAsync(db, login, ct);
            if (principal is null) return Results.NotFound();

            await ctx.SignInAsync(AuthExtensions.CookieScheme, principal);

            audit.RecordSystem("design.session_started", AuditClass.Access,
                subjectId: SubjectId(principal), subjectKind: nameof(Domain.Entities.User),
                detail: $"Claude Design cookie session minted for {login} "
                      + $"from {ctx.Connection.RemoteIpAddress} (TFND-167, dev-only).");
            await db.SaveChangesAsync(ct);

            // Local paths only — never an open redirect out of the app.
            var dest = r is { Length: > 0 } && r.StartsWith('/') && !r.StartsWith("//") && !r.Contains("://")
                ? r
                : "/";
            return Results.Redirect(dest);
        }).AllowAnonymous();

        return app;
    }

    // Inline, cookie-free auth: when the feature is on and a request carries
    // ?__design=<token>, authenticate THAT request as the design login before
    // authorization runs. Registered just before UseAuthorization so the
    // authenticated principal is visible to the auth policy and the prerender.
    public static IApplicationBuilder UseDesignTokenAuth(this IApplicationBuilder app) =>
        app.Use(async (ctx, next) =>
        {
            // Fast path: nothing to do unless the feature is on and the param is
            // actually present. Keeps this a no-op for every normal request.
            if (Enabled && ctx.Request.Query.TryGetValue(QueryParam, out var supplied))
            {
                var secret = Environment.GetEnvironmentVariable(TokenVar);
                var login = Environment.GetEnvironmentVariable(LoginVar);
                if (!string.IsNullOrWhiteSpace(secret) && !string.IsNullOrWhiteSpace(login)
                    && !string.IsNullOrEmpty(supplied) && FixedTimeEquals(supplied!, secret))
                {
                    var db = ctx.RequestServices.GetRequiredService<FindingsDbContext>();
                    var principal = await BuildPrincipalAsync(db, login, ctx.RequestAborted);
                    if (principal is not null)
                    {
                        // Authenticate THIS request (drives authorization + the
                        // Blazor prerender's AuthenticationState).
                        ctx.User = principal;

                        // Courtesy cookie for cookie-capable clients so follow-up
                        // requests (and the interactive circuit) stay signed in
                        // without re-supplying the param. Best-effort — never let
                        // it break the request if the response has begun.
                        if (!ctx.Response.HasStarted)
                        {
                            try { await ctx.SignInAsync(AuthExtensions.CookieScheme, principal); }
                            catch { /* header already flushed; the per-request User still stands */ }
                        }

                        var audit = ctx.RequestServices.GetRequiredService<AuditLog>();
                        audit.RecordSystem("design.request_authenticated", AuditClass.Access,
                            subjectId: SubjectId(principal), subjectKind: nameof(Domain.Entities.User),
                            detail: $"Claude Design inline-token request for {login} "
                                  + $"({ctx.Request.Path}) from {ctx.Connection.RemoteIpAddress} (TFND-167, dev-only).");
                        try { await db.SaveChangesAsync(ctx.RequestAborted); } catch { /* audit is best-effort */ }
                    }
                }
            }

            await next(ctx);
        });

    // The same claim set ExternalSignIn issues, so the principal is
    // indistinguishable from a real sign-in for this user.
    private static async Task<ClaimsPrincipal?> BuildPrincipalAsync(
        FindingsDbContext db, string login, CancellationToken ct)
    {
        var user = await db.Users.FirstOrDefaultAsync(u => u.Login == login && u.IsApproved, ct);
        if (user is null) return null;

        var identity = new ClaimsIdentity(AuthExtensions.CookieScheme);
        identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()));
        identity.AddClaim(new Claim(ClaimTypes.Name, user.Login));
        identity.AddClaim(new Claim(AuthExtensions.TampUserIdClaim, user.Id.ToString()));
        identity.AddClaim(new Claim(AuthExtensions.TampIsAdminClaim, user.IsAdmin.ToString()));
        if (!string.IsNullOrEmpty(user.Email))
            identity.AddClaim(new Claim(ClaimTypes.Email, user.Email));

        return new ClaimsPrincipal(identity);
    }

    private static Guid? SubjectId(ClaimsPrincipal p) =>
        Guid.TryParse(p.FindFirstValue(AuthExtensions.TampUserIdClaim), out var id) ? id : null;

    private static bool FixedTimeEquals(string a, string b) =>
        CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(a), Encoding.UTF8.GetBytes(b));
}
