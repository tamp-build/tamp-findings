using Tamp.Findings.Application.Ingest;
using System.Security.Claims;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Api.Authentication;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Api.Endpoints;

public sealed record MintTokenRequest(string Name);
public sealed record TokenListItem(
    Guid Id,
    string Name,
    string Scope,         // "Client" | "Project"
    string Prefix,        // "cli_" | "prj_"
    Guid? ClientId,
    Guid? ProjectId,
    DateTimeOffset CreatedAt,
    DateTimeOffset? LastUsedAt,
    DateTimeOffset? RevokedAt);

// Token mgmt is admin-only today. Once TFND-3 role assignments are live
// the per-scope check below replaces the IsAdmin gate.
public static class IngestTokenEndpoints
{
    public static IEndpointRouteBuilder MapIngestTokens(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("").WithTags("IngestTokens");

        group.MapPost("/clients/{clientId:guid}/tokens", MintClientAsync)
             .WithName("MintClientIngestToken")
             .WithSummary("Mint a cli_-prefixed bearer token. Authorizes ingest for any project under the named client. Plaintext returned ONCE in the response — store it now or lose it.");
        group.MapGet("/clients/{clientId:guid}/tokens", ListClientAsync)
             .WithName("ListClientIngestTokens")
             .WithSummary("List ingest tokens for a client (metadata only — hashes are not recoverable).");

        group.MapPost("/projects/{projectId:guid}/tokens", MintProjectAsync)
             .WithName("MintProjectIngestToken")
             .WithSummary("Mint a prj_-prefixed bearer token scoped to a single project.");
        group.MapGet("/projects/{projectId:guid}/tokens", ListProjectAsync)
             .WithName("ListProjectIngestTokens")
             .WithSummary("List ingest tokens for a project.");

        group.MapDelete("/tokens/{tokenId:guid}", RevokeAsync)
             .WithName("RevokeIngestToken")
             .WithSummary("Soft-revoke an ingest token. Subsequent uses are rejected; row stays for audit.");

        return app;
    }

    private static async Task<IResult> MintClientAsync(
        Guid clientId, MintTokenRequest req, HttpContext ctx, FindingsDbContext db, IngestTokenService svc, CancellationToken ct)
    {
        var (user, deny) = await RequireAdminAsync(ctx, db, ct);
        if (deny is not null) return deny;
        if (string.IsNullOrWhiteSpace(req.Name)) return Results.BadRequest("name required");
        var exists = await db.Clients.AnyAsync(c => c.Id == clientId, ct);
        if (!exists) return Results.NotFound("client not found");

        var minted = await svc.MintClientTokenAsync(clientId, req.Name.Trim(), user!.Id, ct);
        return Results.Ok(new
        {
            id = minted.Record.Id,
            name = minted.Record.Name,
            // Plaintext exposed exactly once — caller MUST save it now.
            token = minted.Plaintext,
            createdAt = minted.Record.CreatedAt,
        });
    }

    private static async Task<IResult> MintProjectAsync(
        Guid projectId, MintTokenRequest req, HttpContext ctx, FindingsDbContext db, IngestTokenService svc, CancellationToken ct)
    {
        var (user, deny) = await RequireAdminAsync(ctx, db, ct);
        if (deny is not null) return deny;
        if (string.IsNullOrWhiteSpace(req.Name)) return Results.BadRequest("name required");
        var exists = await db.Projects.AnyAsync(p => p.Id == projectId, ct);
        if (!exists) return Results.NotFound("project not found");

        var minted = await svc.MintProjectTokenAsync(projectId, req.Name.Trim(), user!.Id, ct);
        return Results.Ok(new
        {
            id = minted.Record.Id,
            name = minted.Record.Name,
            token = minted.Plaintext,
            createdAt = minted.Record.CreatedAt,
        });
    }

    private static async Task<Ok<IReadOnlyList<TokenListItem>>> ListClientAsync(
        Guid clientId, FindingsDbContext db, CancellationToken ct)
    {
        var rows = await db.IngestTokens.AsNoTracking()
            .Where(t => t.ClientId == clientId)
            .OrderByDescending(t => t.CreatedAt)
            .ToListAsync(ct);
        return TypedResults.Ok((IReadOnlyList<TokenListItem>)rows.Select(Project).ToList());
    }

    private static async Task<Ok<IReadOnlyList<TokenListItem>>> ListProjectAsync(
        Guid projectId, FindingsDbContext db, CancellationToken ct)
    {
        var rows = await db.IngestTokens.AsNoTracking()
            .Where(t => t.ProjectId == projectId)
            .OrderByDescending(t => t.CreatedAt)
            .ToListAsync(ct);
        return TypedResults.Ok((IReadOnlyList<TokenListItem>)rows.Select(Project).ToList());
    }

    private static async Task<IResult> RevokeAsync(
        Guid tokenId, HttpContext ctx, FindingsDbContext db, IngestTokenService svc, CancellationToken ct)
    {
        var (_, deny) = await RequireAdminAsync(ctx, db, ct);
        if (deny is not null) return deny;
        var ok = await svc.RevokeAsync(tokenId, ct);
        return ok ? Results.NoContent() : Results.NotFound();
    }

    private static TokenListItem Project(IngestToken t) => new(
        t.Id,
        t.Name,
        t.Scope.ToString(),
        t.Scope == IngestTokenScope.Client ? IngestTokenService.ClientPrefix : IngestTokenService.ProjectPrefix,
        t.ClientId,
        t.ProjectId,
        t.CreatedAt,
        t.LastUsedAt,
        t.RevokedAt);

    // Returns (user, deny). When deny is non-null, the caller must return
    // it as the endpoint response. Mirrors the /auth/me DB-load posture
    // so admin revocation takes effect immediately.
    private static async Task<(User? user, IResult? deny)> RequireAdminAsync(HttpContext ctx, FindingsDbContext db, CancellationToken ct)
    {
        if (!Guid.TryParse(ctx.User.FindFirstValue(AuthExtensions.TampUserIdClaim), out var uid))
            return (null, Results.Unauthorized());
        var user = await db.Users.FirstOrDefaultAsync(u => u.Id == uid, ct);
        if (user is null || !user.IsApproved) return (null, Results.Unauthorized());
        if (!user.IsAdmin) return (user, Results.Forbid());
        return (user, null);
    }
}
