using Microsoft.AspNetCore.Http.HttpResults;
using Tamp.Findings.Api.Authentication;
using Tamp.Findings.Api.Services;

namespace Tamp.Findings.Api.Endpoints;

public static class SbomEnrichEndpoints
{
    public static IEndpointRouteBuilder MapSbomEnrich(this IEndpointRouteBuilder app)
    {
        app.MapPost("/sbom-components/enrich-versions", EnrichAsync)
           .WithName("EnrichSbomVersions")
           .WithSummary("Look up the latest published version for each SBOM component against nuget.org / registry.npmjs.org and update LatestVersion. Scope to a single snapshot via ?snapshotId=, or omit to enrich every component currently in the DB. Returns a count summary. Requires Authorization: Bearer cli_… or prj_…")
           // AllowAnonymous opts out of the cookie FallbackPolicy; the
           // bearer filter is what actually guards the route. Without the
           // filter this took no body and no required parameter, so an
           // unauthenticated POST enriched EVERY component in the DB —
           // one outbound registry call each, with no rate limiting
           // anywhere in the app. The build already sends the token
           // (IngestClient line 60), so this is a no-op for the pipeline.
           .AllowAnonymous()
           .AddEndpointFilter<IngestAuthFilter>();
        return app;
    }

    private static async Task<Ok<SbomEnrichmentService.Result>> EnrichAsync(
        SbomEnrichmentService service,
        CancellationToken ct,
        Guid? snapshotId = null)
    {
        var result = await service.EnrichAsync(snapshotId, ct);
        return TypedResults.Ok(result);
    }
}
