using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Compliance;
using Tamp.Findings.Data;

namespace Tamp.Findings.Api.Endpoints;

// TFND-191 / ADR 0006 §7: the human VEX-accept action on an ADR-conformance finding.
// Cookie-authed, routed through the capability-gated + audited service (InfoSec AcceptRisk)
// via EndpointActor — the same discipline as the POA&M/VEX writes, never an unaudited
// admin side-door. Accepting a deviation clears the adrConformance gate's block on that one
// finding until the expiry; the finding stays listed.
public static class ConformanceDispositionEndpoints
{
    public sealed record DispositionRequest(string Justification, DateTimeOffset? Expiry);

    public static IEndpointRouteBuilder MapConformanceDisposition(this IEndpointRouteBuilder app)
    {
        app.MapPost("/projects/{projectId:guid}/conformance/{findingId:guid}/disposition", DisposeAsync)
           .WithTags("Compliance")
           .WithSummary("Accept (VEX-disposition) an ADR-conformance finding. Requires the InfoSec AcceptRisk capability. The finding stays listed but stops blocking the adrConformance gate until the expiry.");
        return app;
    }

    private static async Task<IResult> DisposeAsync(
        Guid projectId, Guid findingId, DispositionRequest req, HttpContext ctx,
        FindingsDbContext db, PrincipalResolver principals, ConformanceDispositionService svc,
        CancellationToken ct)
    {
        var (actor, scope, deny) = await EndpointActor.ForProjectAsync(ctx, db, principals, projectId, ct);
        if (deny is not null) return deny;

        var result = await svc.DisposeAsync(actor!, scope, projectId, findingId,
            req.Justification ?? "", req.Expiry, ct);
        if (!result.Success)
            return result.WasDenied
                ? Results.Problem(result.Error, statusCode: StatusCodes.Status403Forbidden)
                : Results.BadRequest(result.Error);

        return Results.Ok(new { findingId = result.Value, dispositioned = true });
    }
}
