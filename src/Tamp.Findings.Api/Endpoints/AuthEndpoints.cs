using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Api.Authentication;
using Tamp.Findings.Data;

namespace Tamp.Findings.Api.Endpoints;

public static class AuthEndpoints
{
    public static IEndpointRouteBuilder MapAuth(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/auth").WithTags("Auth");

        // Kick off the GitHub OAuth dance. SPA hits this directly; the
        // returnUrl flows through the OAuth challenge state and back into
        // the cookie handler, which redirects to it after sign-in.
        group.MapGet("/login/github", (HttpContext ctx, string? returnUrl) =>
        {
            // Only allow same-origin redirects. Prevents an attacker-crafted
            // returnUrl from bouncing the user to an external page after
            // sign-in.
            var safeReturn = !string.IsNullOrEmpty(returnUrl) && returnUrl.StartsWith('/')
                ? returnUrl
                : "/";
            var props = new AuthenticationProperties { RedirectUri = safeReturn };
            return Results.Challenge(props, [AuthExtensions.GitHubScheme]);
        }).AllowAnonymous();

        // Identity probe. SPA calls this on mount; 401 means "show sign-in
        // screen", 200 means "render the dashboard with this user". Reads
        // from the DB by user id (the cookie's only durable claim) so that
        // profile updates — avatar refresh, email backfill, admin
        // demotion — surface immediately without forcing a re-login.
        group.MapGet("/me", async (HttpContext ctx, FindingsDbContext db, CancellationToken ct) =>
        {
            if (ctx.User.Identity?.IsAuthenticated != true)
                return Results.Unauthorized();
            if (!Guid.TryParse(ctx.User.FindFirstValue(AuthExtensions.TampUserIdClaim), out var userId))
                return Results.Unauthorized();
            var user = await db.Users.FirstOrDefaultAsync(u => u.Id == userId, ct);
            // If the row was deleted or approval was revoked, drop the cookie
            // and respond as anonymous so the SPA re-renders SignInView.
            if (user is null || !user.IsApproved)
            {
                await ctx.SignOutAsync(AuthExtensions.CookieScheme);
                return Results.Unauthorized();
            }
            return Results.Ok(new
            {
                id = user.Id,
                login = user.Login,
                displayName = user.DisplayName,
                email = user.Email,
                avatarUrl = user.AvatarUrl,
                isAdmin = user.IsAdmin,
            });
        }).AllowAnonymous();

        group.MapPost("/logout", async (HttpContext ctx) =>
        {
            await ctx.SignOutAsync(AuthExtensions.CookieScheme);
            return Results.NoContent();
        }).AllowAnonymous();

        // Rendered as a tiny HTML page so a user arriving directly from the
        // OAuth failure redirect (without the SPA loaded) still sees a
        // human-readable message. The SPA will overlay its own version when
        // it routes to /auth/denied client-side.
        group.MapGet("/denied", (string? reason) =>
        {
            var msg = reason switch
            {
                "not_approved" => "Your GitHub login is not on the tamp.findings allowlist. Ask an admin to approve it.",
                _ => "Sign-in failed. Try again, or ask an admin if the problem persists.",
            };
            var html = $"<!doctype html><meta charset=\"utf-8\"><title>tamp.findings — access denied</title><body style=\"font-family:system-ui;padding:2rem;max-width:32rem;margin:auto\"><h1>Access denied</h1><p>{System.Net.WebUtility.HtmlEncode(msg)}</p><p><a href=\"/\">Back</a></p></body>";
            return Results.Content(html, "text/html");
        }).AllowAnonymous();

        return app;
    }
}
