using Microsoft.AspNetCore.Http.HttpResults;
using Tamp.Findings.Api.Services;

namespace Tamp.Findings.Api.Endpoints;

public static class SbomEnrichEndpoints
{
    public static IEndpointRouteBuilder MapSbomEnrich(this IEndpointRouteBuilder app)
    {
        app.MapPost("/sbom-components/enrich-versions", EnrichAsync)
           .WithName("EnrichSbomVersions")
           .WithSummary("Look up the latest published version for each SBOM component against nuget.org / registry.npmjs.org and update LatestVersion. Scope to a single snapshot via ?snapshotId=, or omit to enrich every component currently in the DB. Returns a count summary.");
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
