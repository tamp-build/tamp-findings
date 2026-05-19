using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Api.Contracts;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Api.Endpoints;

public static class RoleAssignmentsEndpoints
{
    public static IEndpointRouteBuilder MapRoleAssignments(this IEndpointRouteBuilder app)
    {
        app.MapPost("/role-assignments", CreateAsync)
           .WithName("CreateRoleAssignment")
           .WithSummary("Grant a named role (InfoSecOfficer/LeadDev/Architect) to a user at one tier");

        app.MapGet("/role-assignments", ListAsync)
           .WithName("ListRoleAssignments")
           .WithSummary("List role assignments, optionally filtered by user / role / scope");

        app.MapDelete("/role-assignments/{id:guid}", DeleteAsync)
           .WithName("DeleteRoleAssignment")
           .WithSummary("Revoke a role assignment");

        return app;
    }

    private static async Task<Results<Ok<RoleAssignmentResponse>, BadRequest<string>, NotFound<string>>> CreateAsync(
        RoleAssignmentCreateRequest req,
        FindingsDbContext db,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(req.UserLogin)) return TypedResults.BadRequest("userLogin is required");

        // Exactly one tier must be set. Lower-tier overrides higher (F2.2);
        // a user with both a Client-level and Component-level assignment
        // has TWO distinct rows, not one merged.
        var tiersSet = (req.ClientId is not null ? 1 : 0)
                     + (req.ProjectId is not null ? 1 : 0)
                     + (req.ComponentId is not null ? 1 : 0);
        if (tiersSet != 1) return TypedResults.BadRequest("Exactly one of clientId / projectId / componentId must be set");

        // Resolve user (auto-create — same POC behavior as suppressions).
        var user = await db.Users.FirstOrDefaultAsync(u => u.Login == req.UserLogin, ct);
        if (user is null)
        {
            user = new User { Login = req.UserLogin, DisplayName = req.UserLogin };
            db.Users.Add(user);
            await db.SaveChangesAsync(ct);
        }

        // Validate the referenced entity exists; otherwise the assignment
        // is dangling and the matcher would silently never apply it.
        string? clientName = null, projectName = null, componentName = null;
        if (req.ClientId is { } clientId)
        {
            var c = await db.Clients.AsNoTracking().FirstOrDefaultAsync(x => x.Id == clientId, ct);
            if (c is null) return TypedResults.NotFound("client not found");
            clientName = c.Name;
        }
        if (req.ProjectId is { } projectId)
        {
            var p = await db.Projects.AsNoTracking().Include(p => p.Client).FirstOrDefaultAsync(x => x.Id == projectId, ct);
            if (p is null) return TypedResults.NotFound("project not found");
            projectName = p.Name;
            clientName = p.Client?.Name;
        }
        if (req.ComponentId is { } componentId)
        {
            var c = await db.Components.AsNoTracking().Include(c => c.Project).ThenInclude(p => p!.Client).FirstOrDefaultAsync(x => x.Id == componentId, ct);
            if (c is null) return TypedResults.NotFound("component not found");
            componentName = c.Name;
            projectName = c.Project?.Name;
            clientName = c.Project?.Client?.Name;
        }

        // Idempotency: the unique index already covers
        // (UserId, Role, ClientId, ProjectId, ComponentId). If an identical
        // assignment exists, return it instead of 409 — POST is more
        // ergonomic that way for a script reasserting state.
        var existing = await db.ProjectRoleAssignments.FirstOrDefaultAsync(a =>
            a.UserId == user.Id
            && a.Role == req.Role
            && a.ClientId == req.ClientId
            && a.ProjectId == req.ProjectId
            && a.ComponentId == req.ComponentId, ct);
        if (existing is not null)
        {
            return TypedResults.Ok(ToResponse(existing, user.Login, clientName, projectName, componentName));
        }

        var a = new ProjectRoleAssignment
        {
            UserId = user.Id,
            Role = req.Role,
            ClientId = req.ClientId,
            ProjectId = req.ProjectId,
            ComponentId = req.ComponentId,
        };
        db.ProjectRoleAssignments.Add(a);
        await db.SaveChangesAsync(ct);

        return TypedResults.Ok(ToResponse(a, user.Login, clientName, projectName, componentName));
    }

    private static async Task<Ok<IReadOnlyList<RoleAssignmentResponse>>> ListAsync(
        FindingsDbContext db,
        CancellationToken ct,
        string? userLogin = null,
        ProjectRole? role = null,
        Guid? clientId = null,
        Guid? projectId = null,
        Guid? componentId = null)
    {
        var q = db.ProjectRoleAssignments.AsNoTracking();
        if (role is { } r) q = q.Where(a => a.Role == r);
        if (clientId is { } c) q = q.Where(a => a.ClientId == c);
        if (projectId is { } p) q = q.Where(a => a.ProjectId == p);
        if (componentId is { } co) q = q.Where(a => a.ComponentId == co);

        var joined = await (
            from a in q
            join u in db.Users.AsNoTracking() on a.UserId equals u.Id
            join cli in db.Clients.AsNoTracking() on a.ClientId equals cli.Id into clis
            from cli in clis.DefaultIfEmpty()
            join prj in db.Projects.AsNoTracking() on a.ProjectId equals prj.Id into prjs
            from prj in prjs.DefaultIfEmpty()
            join cmp in db.Components.AsNoTracking() on a.ComponentId equals cmp.Id into cmps
            from cmp in cmps.DefaultIfEmpty()
            where userLogin == null || u.Login == userLogin
            orderby a.CreatedAt descending
            select new { a, u, cli, prj, cmp }
        ).ToListAsync(ct);

        var items = (IReadOnlyList<RoleAssignmentResponse>)joined
            .Select(x => ToResponse(x.a, x.u.Login, x.cli?.Name, x.prj?.Name, x.cmp?.Name))
            .ToList();
        return TypedResults.Ok(items);
    }

    private static async Task<Results<NoContent, NotFound>> DeleteAsync(Guid id, FindingsDbContext db, CancellationToken ct)
    {
        var a = await db.ProjectRoleAssignments.FindAsync([id], ct);
        if (a is null) return TypedResults.NotFound();
        db.ProjectRoleAssignments.Remove(a);
        await db.SaveChangesAsync(ct);
        return TypedResults.NoContent();
    }

    private static RoleAssignmentResponse ToResponse(
        ProjectRoleAssignment a,
        string userLogin,
        string? clientName,
        string? projectName,
        string? componentName)
    {
        var scope = a.ComponentId is not null ? "Component"
                  : a.ProjectId is not null ? "Project"
                  : "Client";
        return new RoleAssignmentResponse(
            a.Id, a.UserId, userLogin, a.Role,
            a.ClientId, clientName,
            a.ProjectId, projectName,
            a.ComponentId, componentName,
            scope, a.CreatedAt);
    }
}
