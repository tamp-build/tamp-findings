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

    /// <summary>
    /// The acting user at an arbitrary scope: a project, a client, or (when neither is given) the instance.
    /// Resolved from the authenticated cookie's user id against the database, never from anything the caller
    /// sends in the body, so what the request ASKS to act on cannot widen what it is ALLOWED to act on.
    /// </summary>
    public static async Task<(Principal? actor, ScopeTarget scope, IResult? deny)> ForScopeAsync(
        HttpContext ctx, FindingsDbContext db, PrincipalResolver principals,
        Guid? clientId, Guid? projectId, CancellationToken ct)
    {
        if (projectId is { } pid) return await ForProjectAsync(ctx, db, principals, pid, ct);

        if (!Guid.TryParse(ctx.User.FindFirstValue(AuthExtensions.TampUserIdClaim), out var uid))
            return (null, default, Results.Unauthorized());

        ScopeTarget scope;
        if (clientId is { } cid)
        {
            if (!await db.Clients.AsNoTracking().AnyAsync(c => c.Id == cid, ct))
                return (null, default, Results.NotFound("client not found"));
            scope = ScopeTarget.Client(cid);
        }
        else scope = ScopeTarget.Instance;

        var actor = await principals.ResolveAsync(uid, scope, ct);
        return actor is null ? (null, scope, Results.Unauthorized()) : (actor, scope, null);
    }
}
