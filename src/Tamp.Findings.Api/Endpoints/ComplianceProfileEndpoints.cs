using Tamp.Findings.Api.Authentication;
using Tamp.Findings.Application.Auditing;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Compliance;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Api.Endpoints;

// TFND-177: the ingest-token-authed compliance profile a conformance producer
// (tamp-conformance, ADR 0006 / core ADR 0023) reads to tag its evidence with
// the correct control vocabulary — the SAME token the evidence flows through, so
// the framework used for extraction is tied to the exact project, no drift by
// construction. Read-only; no findings, no secrets, no cross-project. Pattern
// copied from GateEndpoints (bearer-gated project read).
public static class ComplianceProfileEndpoints
{
    public static IEndpointRouteBuilder MapComplianceProfile(this IEndpointRouteBuilder app)
    {
        app.MapGet("/projects/self/compliance-profile", ProfileAsync)
           .WithName("ComplianceProfile")
           .WithTags("Compliance")
           .WithSummary("The token project's compliance profile — framework, applicable controls, policy templates and enforcement posture. Requires a PROJECT-scoped Authorization: Bearer prj_… token ('self' is unambiguous only for a project token).")
           .AllowAnonymous()
           .AddEndpointFilter<IngestAuthFilter>();
        return app;
    }

    private static async Task<IResult> ProfileAsync(
        HttpContext ctx,
        ComplianceProfileQuery profiles,
        AuditLog audit,
        FindingsDbContext db,
        CancellationToken ct)
    {
        var token = IngestAuthFilter.CurrentToken(ctx);
        if (token is null) return Results.Unauthorized();

        // '/self' resolves the project from the token, which is unambiguous ONLY
        // for a project-scoped token: a client token spans many projects. A
        // client token is refused as not-found rather than 403, so it never
        // confirms which projects exist under the client.
        if (token.Scope != IngestTokenScope.Project || token.ProjectId is not { } projectId)
            return Results.NotFound("compliance profile not found");

        var profile = await profiles.ForProjectAsync(projectId, ct);
        if (profile is null) return Results.NotFound("compliance profile not found");

        // Audit the read (a new authenticated read surface). Attributed to the
        // token's minting user where known.
        audit.RecordIngest(token.Id, token.Name, token.CreatedByUserId, null,
            AuditActions.ComplianceProfileRead,
            new ScopeTarget(token.ClientId, projectId, null),
            detail: $"framework={profile.Framework?.Id ?? "none"}, controls={profile.Controls.Count}");
        await db.SaveChangesAsync(ct);

        return Results.Ok(profile);
    }
}
