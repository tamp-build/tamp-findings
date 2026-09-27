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
//  A pure-URL way for Claude Design (Claude Desktop) to reach the authenticated
//  UI from the cloud, with no interaction on our end. It mints the normal auth
//  cookie for a configured user, so a cloud headless browser that follows the
//  redirect renders the app as that user.
//
//  This is an auth BYPASS on a security product. It is acceptable ONLY because:
//    * it is OFF unless BOTH env vars below are set (absent ⇒ the route 404s,
//      indistinguishable from not existing), so it cannot be on by accident;
//    * the token is a configured secret — rotate or kill it by changing the env,
//      no database artifact, no migration, nothing to clean up;
//    * every use is audited (Access class), and enabling it logs a loud warning.
//
//  Removal = unset the env vars and delete this file + its MapDesignAccess call.
// ─────────────────────────────────────────────────────────────────────────────
public static class DesignAccessEndpoints
{
    public const string TokenVar = "TAMP_FINDINGS_DESIGN_TOKEN";
    public const string LoginVar = "TAMP_FINDINGS_DESIGN_LOGIN";

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

            var user = await db.Users.FirstOrDefaultAsync(u => u.Login == login && u.IsApproved, ct);
            if (user is null) return Results.NotFound();

            // The same claim set ExternalSignIn issues, so the minted cookie is
            // indistinguishable from a real sign-in for this user.
            var identity = new ClaimsIdentity(AuthExtensions.CookieScheme);
            identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()));
            identity.AddClaim(new Claim(ClaimTypes.Name, user.Login));
            identity.AddClaim(new Claim(AuthExtensions.TampUserIdClaim, user.Id.ToString()));
            identity.AddClaim(new Claim(AuthExtensions.TampIsAdminClaim, user.IsAdmin.ToString()));
            if (!string.IsNullOrEmpty(user.Email))
                identity.AddClaim(new Claim(ClaimTypes.Email, user.Email));

            await ctx.SignInAsync(AuthExtensions.CookieScheme, new ClaimsPrincipal(identity));

            audit.RecordSystem("design.session_started", AuditClass.Access,
                subjectId: user.Id, subjectKind: nameof(Domain.Entities.User),
                detail: $"Claude Design access session minted for {user.Login} "
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

    private static bool FixedTimeEquals(string a, string b) =>
        CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(a), Encoding.UTF8.GetBytes(b));
}
