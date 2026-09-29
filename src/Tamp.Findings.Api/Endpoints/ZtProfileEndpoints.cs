using Tamp.Findings.Api.Authentication;
using Tamp.Findings.Application.Auditing;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Zt;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Api.Endpoints;

// TFND-188 / ADR 0010: the ingest-token-authed ZT ruleset a tamp-ztt analyzer reads to
// know WHAT to score — the ZTMM model + the in-force operational mandate definitions —
// using the SAME token its results flow back through (/ingest/conformance). ztt is
// analysis-only; findings is the system of record. Pattern copied from
// ComplianceProfileEndpoints (bearer-gated project read).
public static class ZtProfileEndpoints
{
    public static IEndpointRouteBuilder MapZtProfile(this IEndpointRouteBuilder app)
    {
        app.MapGet("/projects/self/zt-profile", ProfileAsync)
           .WithName("ZtProfile")
           .WithTags("Compliance")
           .WithSummary("The token project's Zero Trust ruleset — the ZTMM model and the in-force operational mandate definitions. Requires a PROJECT-scoped Authorization: Bearer prj_… token.")
           .AllowAnonymous()
           .AddEndpointFilter<IngestAuthFilter>();
        return app;
    }

    private static async Task<IResult> ProfileAsync(
        HttpContext ctx,
        ZtProfileQuery profiles,
        AuditLog audit,
        FindingsDbContext db,
        CancellationToken ct)
    {
        var token = IngestAuthFilter.CurrentToken(ctx);
        if (token is null) return Results.Unauthorized();

        // 'self' is unambiguous only for a project token; a client token is refused as
        // not-found (never 403), so it cannot confirm which projects exist.
        if (token.Scope != IngestTokenScope.Project || token.ProjectId is not { } projectId)
            return Results.NotFound("zt profile not found");

        var profile = await profiles.ForProjectAsync(projectId, ct);
        if (profile is null) return Results.NotFound("zt profile not found");

        audit.RecordIngest(token.Id, token.Name, token.CreatedByUserId, null,
            AuditActions.ZtProfileRead,
            new ScopeTarget(token.ClientId, projectId),
            detail: $"model={profile.Model.Name} {profile.Model.Version}, mandates={profile.Mandates.Count}");
        await db.SaveChangesAsync(ct);

        return Results.Ok(profile);
    }
}
