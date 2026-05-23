using Microsoft.Net.Http.Headers;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Api.Authentication;

// EndpointFilter applied to every /ingest/* route. Extracts the bearer
// token, validates it via IngestTokenService, and stashes the live row
// on HttpContext.Items for the endpoint to scope-check against the
// resolved Client/Project from the request body.
public sealed class IngestAuthFilter(IngestTokenService tokens) : IEndpointFilter
{
    public const string TokenKey = "tamp.ingest.token";

    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext ctx, EndpointFilterDelegate next)
    {
        var header = ctx.HttpContext.Request.Headers[HeaderNames.Authorization].ToString();
        if (string.IsNullOrWhiteSpace(header) || !header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            return Results.Unauthorized();

        var wire = header["Bearer ".Length..].Trim();
        var row = await tokens.ValidateAsync(wire, ctx.HttpContext.RequestAborted);
        if (row is null) return Results.Unauthorized();

        ctx.HttpContext.Items[TokenKey] = row;
        return await next(ctx);
    }

    // Helper for ingest endpoints: read the validated token off the
    // context. Returns null if the filter wasn't applied (shouldn't
    // happen for /ingest/* routes).
    public static IngestToken? CurrentToken(HttpContext ctx)
        => ctx.Items.TryGetValue(TokenKey, out var v) ? v as IngestToken : null;
}

// Token-aware Client + Project resolver. Replaces the per-endpoint
// auto-create-on-name pattern with a strict lookup that scope-checks
// against the bearer token:
//   - cli_ token: Client must exist AND match token.ClientId.
//                 Project auto-creates under that client if missing.
//   - prj_ token: Client must exist AND own the project; Project must
//                 exist AND match token.ProjectId.
// Component/Version/Flavor creation downstream is unchanged — anything
// under the matched scope can be created on first sight.
public static class IngestScopeGuard
{
    public static async Task<(Client? client, Project? project, IResult? error)> ResolveAndGuardAsync(
        Microsoft.EntityFrameworkCore.DbContext db,
        IngestToken? token,
        string clientName,
        string projectName,
        CancellationToken ct)
    {
        if (token is null) return (null, null, Results.Unauthorized());

        var clientSet = ((Tamp.Findings.Data.FindingsDbContext)db).Clients;
        var projectSet = ((Tamp.Findings.Data.FindingsDbContext)db).Projects;

        var client = await Microsoft.EntityFrameworkCore.EntityFrameworkQueryableExtensions
            .FirstOrDefaultAsync(clientSet, c => c.Name == clientName, ct);
        if (client is null)
            return (null, null, Results.NotFound($"client '{clientName}' not found"));

        if (token.Scope == IngestTokenScope.Client && client.Id != token.ClientId)
            return (null, null, Results.Forbid());

        var project = await Microsoft.EntityFrameworkCore.EntityFrameworkQueryableExtensions
            .FirstOrDefaultAsync(projectSet, p => p.ClientId == client.Id && p.Name == projectName, ct);

        if (token.Scope == IngestTokenScope.Project)
        {
            if (project is null)
                return (null, null, Results.NotFound($"project '{projectName}' under '{clientName}' not found"));
            if (project.Id != token.ProjectId)
                return (null, null, Results.Forbid());
        }
        else
        {
            // cli_ scope: project auto-creates under the matched client.
            if (project is null)
            {
                project = new Project { ClientId = client.Id, Name = projectName };
                ((Tamp.Findings.Data.FindingsDbContext)db).Projects.Add(project);
            }
        }
        return (client, project, null);
    }
}
