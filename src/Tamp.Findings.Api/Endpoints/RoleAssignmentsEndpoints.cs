using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Api.Contracts;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.SystemAdmin;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Api.Endpoints;

// Role assignments over HTTP (TFND-228). Granting, revoking and even LISTING who holds which role is an
// access-control decision, so every operation here is authorized against the scope it acts on, with the acting
// user resolved from the authenticated cookie and checked for Capability.AssignRoles (Admin / InfoSec). Grant
// and revoke go through SystemAdminService, the audited path the UI uses, so separation-of-duties and the audit
// trail apply identically however the request arrives. Nothing in the request body decides what the caller may do.
public static class RoleAssignmentsEndpoints
{
    public static IEndpointRouteBuilder MapRoleAssignments(this IEndpointRouteBuilder app)
    {
        app.MapPost("/role-assignments", CreateAsync)
           .WithName("CreateRoleAssignment")
           .WithSummary("Grant a named role (InfoSecOfficer/LeadDev/Architect) to a user at one tier. Requires AssignRoles at that tier.");

        app.MapGet("/role-assignments", ListAsync)
           .WithName("ListRoleAssignments")
           .WithSummary("List role assignments, optionally filtered by user / role / scope. Requires AssignRoles at the filtered scope (instance-wide when unfiltered).");

        app.MapDelete("/role-assignments/{id:guid}", DeleteAsync)
           .WithName("DeleteRoleAssignment")
           .WithSummary("Revoke a role assignment. Requires AssignRoles at the assignment's tier.");

        return app;
    }

    private static async Task<IResult> CreateAsync(
        RoleAssignmentCreateRequest req, HttpContext ctx, FindingsDbContext db,
        PrincipalResolver principals, SystemAdminService admin, CapabilityEvaluator capabilities, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(req.UserLogin)) return Results.BadRequest("userLogin is required");

        // Exactly one tier must be set. Lower-tier overrides higher (F2.2); a user with both a Client-level and
        // Project-level assignment has TWO distinct rows, not one merged.
        var tiersSet = (req.ClientId is not null ? 1 : 0) + (req.ProjectId is not null ? 1 : 0);
        if (tiersSet != 1) return Results.BadRequest("Exactly one of clientId / projectId must be set");

        // Authorize at the scope being granted AT, before anything is written or any user is created.
        var (actor, scope, deny) = await EndpointActor.ForScopeAsync(ctx, db, principals, req.ClientId, req.ProjectId, ct);
        if (deny is not null) return deny;
        var decision = capabilities.Evaluate(actor!, Capability.AssignRoles);
        if (!decision.Allowed) return Results.Problem(decision.Reason, statusCode: StatusCodes.Status403Forbidden);

        string? clientName = null, projectName = null;
        if (req.ProjectId is { } projectId)
        {
            var p = await db.Projects.AsNoTracking().Include(x => x.Client).FirstAsync(x => x.Id == projectId, ct);
            projectName = p.Name;
            clientName = p.Client?.Name;
        }
        else if (req.ClientId is { } clientId)
            clientName = await db.Clients.AsNoTracking().Where(c => c.Id == clientId).Select(c => c.Name).FirstAsync(ct);

        // Resolve the user (an authorized granter may pre-provision a login, as before; they sign in later).
        var user = await db.Users.FirstOrDefaultAsync(u => u.Login == req.UserLogin, ct);
        if (user is null)
        {
            user = new User { Login = req.UserLogin, DisplayName = req.UserLogin };
            db.Users.Add(user);
            await db.SaveChangesAsync(ct);
        }

        // Idempotent for a script reasserting state: an identical assignment is returned, not a 409.
        // A project grant matches on the project alone: rows created through the service carry the client id
        // too, rows created by older callers did not.
        var existing = await db.ProjectRoleAssignments.FirstOrDefaultAsync(a =>
            a.UserId == user.Id && a.Role == req.Role
            && (req.ProjectId != null ? a.ProjectId == req.ProjectId : (a.ClientId == req.ClientId && a.ProjectId == null)), ct);
        if (existing is not null)
            return Results.Ok(ToResponse(existing, user.Login, clientName, projectName));

        var result = await admin.GrantAsync(actor!, user.Id, req.Role, scope, ct);
        if (!result.Success)
            return result.WasDenied
                ? Results.Problem(result.Error, statusCode: StatusCodes.Status403Forbidden)
                : Results.BadRequest(result.Error);

        var created = await db.ProjectRoleAssignments.AsNoTracking().FirstAsync(a => a.Id == result.Value, ct);
        return Results.Ok(ToResponse(created, user.Login, clientName, projectName));
    }

    private static async Task<IResult> ListAsync(
        HttpContext ctx, FindingsDbContext db, PrincipalResolver principals, CapabilityEvaluator capabilities,
        CancellationToken ct,
        string? userLogin = null, ProjectRole? role = null, Guid? clientId = null, Guid? projectId = null)
    {
        // Who holds which role is itself sensitive, so listing needs AssignRoles at the scope being listed
        // (the instance, when no scope filter is given).
        var (actor, _, deny) = await EndpointActor.ForScopeAsync(ctx, db, principals, clientId, projectId, ct);
        if (deny is not null) return deny;
        var decision = capabilities.Evaluate(actor!, Capability.AssignRoles);
        if (!decision.Allowed) return Results.Problem(decision.Reason, statusCode: StatusCodes.Status403Forbidden);

        var q = db.ProjectRoleAssignments.AsNoTracking();
        if (role is { } r) q = q.Where(a => a.Role == r);
        if (clientId is { } c) q = q.Where(a => a.ClientId == c);
        if (projectId is { } p) q = q.Where(a => a.ProjectId == p);

        var joined = await (
            from a in q
            join u in db.Users.AsNoTracking() on a.UserId equals u.Id
            join cli in db.Clients.AsNoTracking() on a.ClientId equals cli.Id into clis
            from cli in clis.DefaultIfEmpty()
            join prj in db.Projects.AsNoTracking() on a.ProjectId equals prj.Id into prjs
            from prj in prjs.DefaultIfEmpty()
            where userLogin == null || u.Login == userLogin
            orderby a.CreatedAt descending
            select new { a, u, cli, prj }
        ).ToListAsync(ct);

        IReadOnlyList<RoleAssignmentResponse> items = joined
            .Select(x => ToResponse(x.a, x.u.Login, x.cli?.Name, x.prj?.Name))
            .ToList();
        return Results.Ok(items);
    }

    private static async Task<IResult> DeleteAsync(
        Guid id, HttpContext ctx, FindingsDbContext db, PrincipalResolver principals,
        SystemAdminService admin, CapabilityEvaluator capabilities, CancellationToken ct)
    {
        var assignment = await db.ProjectRoleAssignments.AsNoTracking().FirstOrDefaultAsync(a => a.Id == id, ct);
        if (assignment is null) return Results.NotFound();

        // Authorize at the tier the assignment lives at, so a LeadDev elsewhere cannot revoke it.
        var (actor, _, deny) = await EndpointActor.ForScopeAsync(ctx, db, principals, assignment.ClientId, assignment.ProjectId, ct);
        if (deny is not null) return deny;
        var decision = capabilities.Evaluate(actor!, Capability.AssignRoles);
        if (!decision.Allowed) return Results.Problem(decision.Reason, statusCode: StatusCodes.Status403Forbidden);

        var result = await admin.RevokeAsync(actor!, id, ct);
        return result.Success && result.Value ? Results.NoContent()
            : result.WasDenied ? Results.Problem(result.Error, statusCode: StatusCodes.Status403Forbidden)
            : Results.NotFound();
    }

    private static RoleAssignmentResponse ToResponse(
        ProjectRoleAssignment a, string userLogin, string? clientName, string? projectName)
    {
        var scope = a.ProjectId is not null ? "Project" : "Client";
        return new RoleAssignmentResponse(
            a.Id, a.UserId, userLogin, a.Role,
            a.ClientId, clientName,
            a.ProjectId, projectName,
            scope, a.CreatedAt);
    }
}
