using Tamp.Findings.Application.Attestation;

namespace Tamp.Findings.Api.Endpoints;

// CISA Secure Software Development Attestation.
//
// The document itself is built by SsdfAttestationBuilder in Application: the
// Blazor attestation screen needs the same document and Web must not reference
// Api (ADR 0002). This endpoint is the machine-readable surface over it — the
// JSON here is the artefact that goes into a FedRAMP package.
public static class SsdfAttestationEndpoints
{
    public static IEndpointRouteBuilder MapSsdfAttestation(this IEndpointRouteBuilder app)
    {
        app.MapGet("/projects/{projectId:guid}/ssdf-attestation", BuildAsync)
           .WithName("SsdfAttestation")
           .WithTags("Attestation")
           .WithSummary("CISA SSDF (SP 800-218) attestation doc populated from ingest data — risk score, gate state, KEV exposure, VEX coverage, POA&M lifecycle, SBOM hygiene.");
        return app;
    }

    private static async Task<IResult> BuildAsync(
        Guid projectId,
        string? commitSha,
        SsdfAttestationBuilder builder,
        CancellationToken ct)
    {
        var doc = await builder.BuildAsync(projectId, commitSha, ct);
        return doc is null
            ? Results.NotFound("project not found, or no default risk policy seeded")
            : Results.Ok(doc);
    }
}
