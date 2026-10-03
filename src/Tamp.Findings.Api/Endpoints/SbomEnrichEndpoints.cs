using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Api.Authentication;
using Tamp.Findings.Api.Services;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Api.Endpoints;

public static class SbomEnrichEndpoints
{
    public static IEndpointRouteBuilder MapSbomEnrich(this IEndpointRouteBuilder app)
    {
        app.MapPost("/sbom-components/enrich-versions", EnrichAsync)
           .WithName("EnrichSbomVersions")
           .WithSummary("Look up the latest published version for each component of ONE SBOM snapshot against nuget.org / registry.npmjs.org and update LatestVersion / license. ?snapshotId= is required and the snapshot must belong to the token's own scope (a project token: its project; a client token: any project under that client). Returns a count summary. Requires Authorization: Bearer cli_… or prj_…")
           // AllowAnonymous opts out of the cookie FallbackPolicy; the bearer filter is what actually guards
           // the route. The build already sends the token (IngestClient), so this is a no-op for the pipeline.
           .AllowAnonymous()
           .AddEndpointFilter<IngestAuthFilter>();
        return app;
    }

    // TFND-229: this used to accept ANY valid ingest token and, with no snapshotId, enrich every component of
    // every tenant — an instance-wide fan-out of outbound registry calls (one per component) and cross-tenant
    // writes to LatestVersion / License, triggerable by a single project-scoped token. snapshotId is now
    // required and must belong to the token's own scope; anything else is a 404, so a token cannot probe
    // whether another tenant's snapshot exists.
    private static async Task<IResult> EnrichAsync(
        HttpContext ctx,
        FindingsDbContext db,
        SbomEnrichmentService service,
        CancellationToken ct,
        Guid? snapshotId = null)
    {
        if (snapshotId is not { } id)
            return Results.BadRequest("snapshotId is required: enrichment is scoped to one SBOM snapshot");

        var token = IngestAuthFilter.CurrentToken(ctx);
        if (token is null) return Results.Unauthorized();

        var owner = await db.SbomSnapshots.AsNoTracking()
            .Where(s => s.Id == id)
            .Select(s => new { s.ComponentVersion!.ProjectId, ClientId = s.ComponentVersion.Project!.ClientId })
            .FirstOrDefaultAsync(ct);

        var inScope = owner is not null && (token.Scope == IngestTokenScope.Project
            ? token.ProjectId == owner.ProjectId
            : token.ClientId == owner.ClientId);
        if (!inScope) return Results.NotFound();

        return Results.Ok(await service.EnrichAsync(id, ct));
    }
}
