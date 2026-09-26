using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Api.Authentication;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Data;

namespace Tamp.Findings.Api.Endpoints;

// Resolves the cookie user to a capability-bearing Principal at a project scope
// (TFND-156, ADR 0002). The VEX / POA&M / gate write endpoints use this to route
// through the audited, capability-gated Application services instead of the old
// Admin-only, unaudited path that could, for example, set a POA&M RiskAccepted
// without the InfoSec AcceptRisk capability.
//
// The user id comes from the authenticated cookie and the admin flag is read
// from the DB by PrincipalResolver — nothing the client sends decides access.
internal static class EndpointActor
{
    public static async Task<(Principal? actor, ScopeTarget scope, IResult? deny)> ForProjectAsync(
        HttpContext ctx, FindingsDbContext db, PrincipalResolver principals, Guid projectId, CancellationToken ct)
    {
        if (!Guid.TryParse(ctx.User.FindFirstValue(AuthExtensions.TampUserIdClaim), out var uid))
            return (null, default, Results.Unauthorized());

        var clientId = await db.Projects.AsNoTracking()
            .Where(p => p.Id == projectId)
            .Select(p => (Guid?)p.ClientId)
            .FirstOrDefaultAsync(ct);
        if (clientId is null) return (null, default, Results.NotFound("project not found"));

        var scope = ScopeTarget.Project(clientId.Value, projectId);
        var actor = await principals.ResolveAsync(uid, scope, ct);
        // PrincipalResolver returns null for an unknown or unapproved user — a
        // denial, never a Viewer.
        if (actor is null) return (null, scope, Results.Unauthorized());

        return (actor, scope, null);
    }
}
