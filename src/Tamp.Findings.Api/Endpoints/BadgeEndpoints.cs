using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Api.Authentication;
using Tamp.Findings.Application.Projects;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Api.Endpoints;

// The public status badge (Project.BadgeKey). The SVG is ANONYMOUS and read-only — the unguessable
// key in the URL is the capability; an admin can rotate it to revoke a leaked embed. The image is
// never cached (headers below); a proxy like GitHub camo may still cache it, which is why the badge
// itself carries the build sha + timestamp so a stale copy is self-evident.
public static class BadgeEndpoints
{
    public static IEndpointRouteBuilder MapBadge(this IEndpointRouteBuilder app)
    {
        app.MapGet("/badge/{key}.svg", PublicBadgeAsync)
           .WithName("PublicBadge")
           .WithSummary("Public status badge for a project (anonymous). The key is the per-project BadgeKey. Never cached.")
           .AllowAnonymous();

        // Admin: mint/read the key + rotate it. Behind the fallback auth policy; admin-checked inline.
        app.MapGet("/projects/{projectId:guid}/badge", GetBadgeInfoAsync)
           .WithName("GetBadgeInfo")
           .WithSummary("The project's badge key + embed snippet (mints one if absent). Admin only.");
        app.MapPost("/projects/{projectId:guid}/badge/rotate", RotateBadgeAsync)
           .WithName("RotateBadgeKey")
           .WithSummary("Rotate the project's badge key, revoking any existing embed. Admin only.");
        return app;
    }

    private static async Task<IResult> PublicBadgeAsync(
        string key, HttpContext ctx, FindingsDbContext db, ProjectHubQuery hub, CancellationToken ct)
    {
        NoStore(ctx);
        if (string.IsNullOrWhiteSpace(key)) return Results.NotFound();

        var project = await db.Projects.AsNoTracking()
            .Include(p => p.Client)
            .FirstOrDefaultAsync(p => p.BadgeKey == key, ct);
        if (project is null || project.Client is null) return Results.NotFound();

        // The key IS the authorization, so we build the ProjectRef directly (no visibility check —
        // that guards signed-in tenant reads, not the opt-in public badge).
        var pref = new ProjectRef(project.ClientId, project.Client.Name, project.Id, project.Name,
            project.RiskPolicyId, project.GatesConfig);
        var data = await hub.LoadAsync(pref, commitSha: null, ct);

        var svg = data is null
            ? BadgeSvg.RenderUnbuilt(project.Name, Subtitle(project.Client.Name, data))
            : BadgeSvg.Render(ProjectStatus.From(data), DateTimeOffset.UtcNow);

        return Results.Text(svg, "image/svg+xml", System.Text.Encoding.UTF8);
    }

    private static async Task<IResult> GetBadgeInfoAsync(
        Guid projectId, HttpContext ctx, FindingsDbContext db, CancellationToken ct)
    {
        var deny = await RequireAdminAsync(ctx, db, ct);
        if (deny is not null) return deny;
        var project = await db.Projects.FirstOrDefaultAsync(p => p.Id == projectId, ct);
        if (project is null) return Results.NotFound();
        if (string.IsNullOrWhiteSpace(project.BadgeKey))
        {
            project.BadgeKey = NewKey();
            await db.SaveChangesAsync(ct);
        }
        return Results.Ok(Info(ctx, project.BadgeKey!, project));
    }

    private static async Task<IResult> RotateBadgeAsync(
        Guid projectId, HttpContext ctx, FindingsDbContext db, CancellationToken ct)
    {
        var deny = await RequireAdminAsync(ctx, db, ct);
        if (deny is not null) return deny;
        var project = await db.Projects.FirstOrDefaultAsync(p => p.Id == projectId, ct);
        if (project is null) return Results.NotFound();
        project.BadgeKey = NewKey();
        await db.SaveChangesAsync(ct);
        return Results.Ok(Info(ctx, project.BadgeKey!, project));
    }

    private static object Info(HttpContext ctx, string key, Project project)
    {
        var origin = $"{ctx.Request.Scheme}://{ctx.Request.Host}";
        var url = $"{origin}/badge/{key}.svg";
        // TFND-215: when the public report is on, the badge links to the full evidence behind it.
        var target = project.PublicReportEnabled && !string.IsNullOrWhiteSpace(project.ReportKey)
            ? $"{origin}/report/{project.ReportKey}" : origin;
        return new
        {
            key,
            url,
            markdown = $"[![tamp-findings]({url})]({target})",
            html = $"<a href=\"{target}\"><img src=\"{url}\" alt=\"tamp-findings status\"></a>",
        };
    }

    private static string? Subtitle(string client, ProjectHubData? data) =>
        data?.ComplianceBaseline is { Length: > 0 } bl ? $"{client} · {bl}" : client;

    // 128 bits, hex — opaque + unguessable, url-safe, fits the 64-char column.
    private static string NewKey() => Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));

    private static void NoStore(HttpContext ctx)
    {
        ctx.Response.Headers.CacheControl = "no-store, no-cache, must-revalidate, max-age=0";
        ctx.Response.Headers.Pragma = "no-cache";
        ctx.Response.Headers.Expires = "0";
    }

    private static async Task<IResult?> RequireAdminAsync(HttpContext ctx, FindingsDbContext db, CancellationToken ct)
    {
        if (!Guid.TryParse(ctx.User.FindFirstValue(AuthExtensions.TampUserIdClaim), out var uid))
            return Results.Unauthorized();
        var user = await db.Users.FirstOrDefaultAsync(u => u.Id == uid, ct);
        if (user is null || !user.IsApproved) return Results.Unauthorized();
        if (!user.IsAdmin) return Results.Forbid();
        return null;
    }
}
