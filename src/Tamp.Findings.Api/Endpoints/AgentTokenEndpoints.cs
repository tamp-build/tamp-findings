using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Mcp;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Api.Endpoints;

public sealed record MintAgentTokenRequest(string Name, string? Role = null, int? ExpiresInDays = null);

public sealed record MintedAgentTokenResponse(
    Guid Id,
    string Name,
    string Scope,
    /// <summary>
    /// The bearer value, returned ONCE. Only a hash is stored, so there is no
    /// second chance to read it.
    /// </summary>
    string Token);

// Minting an agent token over HTTP (TFND-259).
//
// MintAsync was callable from exactly two Razor pages and from nowhere else, so
// getting an agent onto the MCP surface required a browser AND a navigable
// client page. On a fresh instance that made the whole agent surface
// unreachable: no client page meant no token, and the cli_/prj_ INGEST tokens
// that can be minted over HTTP are rejected at /mcp by design — different
// prefix, different trust model.
//
// An agent should never need a UI to exist in order to interrogate findings, and
// that is all this fixes. What it deliberately does NOT change:
//
//  - The scope rule. MintAsync still refuses a scope with no client, because an
//    instance-wide read token is a standing grant over every tenant and the read
//    tools expose every finding, SBOM, suppression and disposition in scope. The
//    scope IS the blast radius.
//  - The capability. Minting access needs AssignRoles, the capability that
//    grants access, not the one that manages CI keys — the same gate the UI
//    goes through, because the service owns it.
//  - InfoSecOfficer is still refused for any agent (TFND-242, ADR 0019 §6).
//
// Project scope is the one to reach for: a project implies its client, so
// ScopeTarget.Project carries both and nothing extra has to be supplied. The
// client-scoped route is for an agent that genuinely spans a tenant's portfolio.
public static class AgentTokenEndpoints
{
    public static IEndpointRouteBuilder MapAgentTokens(this IEndpointRouteBuilder app)
    {
        var g = app.MapGroup("").WithTags("AgentTokens");

        g.MapPost("/projects/{projectId:guid}/agent-tokens", MintForProjectAsync)
         .WithName("MintProjectAgentToken")
         .WithSummary("Mint an mcp_-prefixed agent token scoped to one project — the recommended scope. Needs AssignRoles. Plaintext returned ONCE.");

        g.MapPost("/clients/{clientId:guid}/agent-tokens", MintForClientAsync)
         .WithName("MintClientAgentToken")
         .WithSummary("Mint an mcp_-prefixed agent token spanning every project under a client. Needs AssignRoles. Plaintext returned ONCE.");

        g.MapGet("/projects/{projectId:guid}/agent-tokens", ListForProjectAsync)
         .WithName("ListProjectAgentTokens")
         .WithSummary("Agent tokens at or below this project (metadata only — the plaintext is not recoverable).");

        g.MapGet("/clients/{clientId:guid}/agent-tokens", ListForClientAsync)
         .WithName("ListClientAgentTokens")
         .WithSummary("Agent tokens at or below this client.");

        g.MapDelete("/agent-tokens/{tokenId:guid}", RevokeAsync)
         .WithName("RevokeAgentToken")
         .WithSummary("Revoke an agent token. It stops resolving on its next request; the row stays for audit.");

        return app;
    }

    private static async Task<IResult> MintForProjectAsync(
        Guid projectId, MintAgentTokenRequest req, HttpContext ctx, FindingsDbContext db,
        PrincipalResolver principals, McpTokenService tokens, CancellationToken ct)
    {
        var (actor, scope, deny) = await EndpointActor.ForProjectAsync(ctx, db, principals, projectId, ct);
        if (deny is not null) return deny;

        return await MintAsync(actor!, scope, req, tokens, ct);
    }

    private static async Task<IResult> MintForClientAsync(
        Guid clientId, MintAgentTokenRequest req, HttpContext ctx, FindingsDbContext db,
        PrincipalResolver principals, McpTokenService tokens, CancellationToken ct)
    {
        var (actor, scope, deny) = await EndpointActor.ForScopeAsync(
            ctx, db, principals, clientId, projectId: null, ct);
        if (deny is not null) return deny;

        return await MintAsync(actor!, scope, req, tokens, ct);
    }

    private static async Task<IResult> MintAsync(
        Principal actor, ScopeTarget scope, MintAgentTokenRequest req,
        McpTokenService tokens, CancellationToken ct)
    {
        // An unparseable role is refused rather than silently dropped. Falling
        // back to Viewer would hand back a token quieter than the caller asked
        // for, and they would not find out until an agent could not export.
        ProjectRole? role = null;
        if (req.Role is { Length: > 0 } wanted)
        {
            if (!Enum.TryParse<ProjectRole>(wanted, ignoreCase: true, out var parsed))
            {
                return Results.BadRequest(
                    $"'{wanted}' is not a role. Use {string.Join(", ", Enum.GetNames<ProjectRole>())}.");
            }
            role = parsed;
        }

        var result = await tokens.MintAsync(actor, scope, req.Name ?? "", role, req.ExpiresInDays, ct);

        if (result.WasDenied) return Results.Forbid();
        if (!result.Success) return Results.BadRequest(result.Error);

        return Results.Created(
            $"/agent-tokens/{result.Value!.Id}",
            new MintedAgentTokenResponse(
                result.Value.Id,
                req.Name!.Trim(),
                scope.ProjectId is not null ? "Project" : "Client",
                result.Value.Plaintext));
    }

    private static async Task<IResult> ListForProjectAsync(
        Guid projectId, HttpContext ctx, FindingsDbContext db,
        PrincipalResolver principals, McpTokenService tokens, CancellationToken ct)
    {
        var (_, scope, deny) = await EndpointActor.ForProjectAsync(ctx, db, principals, projectId, ct);
        if (deny is not null) return deny;

        return Results.Ok(await tokens.ListAsync(scope, DateTimeOffset.UtcNow, ct));
    }

    private static async Task<IResult> ListForClientAsync(
        Guid clientId, HttpContext ctx, FindingsDbContext db,
        PrincipalResolver principals, McpTokenService tokens, CancellationToken ct)
    {
        var (_, scope, deny) = await EndpointActor.ForScopeAsync(
            ctx, db, principals, clientId, projectId: null, ct);
        if (deny is not null) return deny;

        return Results.Ok(await tokens.ListAsync(scope, DateTimeOffset.UtcNow, ct));
    }

    private static async Task<IResult> RevokeAsync(
        Guid tokenId, HttpContext ctx, FindingsDbContext db,
        PrincipalResolver principals, McpTokenService tokens, CancellationToken ct)
    {
        // The token's OWN scope decides who may revoke it, read from the row
        // rather than from anything the caller sends — otherwise a request could
        // name a scope it holds and revoke a token belonging to one it does not.
        var row = await db.McpTokens.AsNoTracking()
            .Where(t => t.Id == tokenId)
            .Select(t => new { t.ClientId, t.ProjectId })
            .FirstOrDefaultAsync(ct);
        if (row is null) return Results.NotFound("agent token not found");

        var (actor, scope, deny) = await EndpointActor.ForScopeAsync(
            ctx, db, principals, row.ClientId, row.ProjectId, ct);
        if (deny is not null) return deny;

        var result = await tokens.RevokeAsync(actor!, scope, tokenId, ct);

        if (result.WasDenied) return Results.Forbid();
        if (!result.Success) return Results.BadRequest(result.Error);

        return Results.NoContent();
    }
}
