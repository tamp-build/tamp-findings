using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Api.Authentication;
using Tamp.Findings.Api.Contracts;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Api.Endpoints;

// Create-side counterparts to the GET /clients|/projects|/components
// list endpoints in FindingsListEndpoints. Admin-gated; the AddMenu in
// the SPA header surfaces these.
//
// Up-front validation is minimal — non-blank Name, uniqueness within
// scope, FK existence. EF's unique index constraints catch concurrent
// races and surface as 409.
public sealed record CreateClientRequest(string Name);
public sealed record CreateProjectRequest(string Name, Guid ClientId, string? Description);
public sealed record CreateComponentRequest(string Name, Guid ProjectId, string? Kind);

public static class HierarchyCreateEndpoints
{
    public static IEndpointRouteBuilder MapHierarchyCreate(this IEndpointRouteBuilder app)
    {
        var g = app.MapGroup("").WithTags("Hierarchy");

        g.MapPost("/clients", CreateClientAsync)
         .WithSummary("Create a client. Admin only.");
        g.MapPost("/projects", CreateProjectAsync)
         .WithSummary("Create a project under a client. Admin only.");
        g.MapPost("/components", CreateComponentAsync)
         .WithSummary("Create a component under a project. Admin only.");
        return app;
    }

    private static async Task<IResult> CreateClientAsync(
        CreateClientRequest req, HttpContext ctx, FindingsDbContext db, CancellationToken ct)
    {
        var (_, deny) = await RequireAdminAsync(ctx, db, ct);
        if (deny is not null) return deny;
        var name = req.Name?.Trim();
        if (string.IsNullOrWhiteSpace(name)) return Results.BadRequest("name required");

        var row = new Client { Name = name };
        db.Clients.Add(row);
        try { await db.SaveChangesAsync(ct); }
        catch (DbUpdateException) { return Results.Conflict("client name already exists"); }

        return Results.Created($"/clients/{row.Id}",
            new ClientListItem(row.Id, row.Name, 0, row.RiskPolicyId));
    }

    private static async Task<IResult> CreateProjectAsync(
        CreateProjectRequest req, HttpContext ctx, FindingsDbContext db, CancellationToken ct)
    {
        var (_, deny) = await RequireAdminAsync(ctx, db, ct);
        if (deny is not null) return deny;
        var name = req.Name?.Trim();
        if (string.IsNullOrWhiteSpace(name)) return Results.BadRequest("name required");

        var client = await db.Clients.AsNoTracking().FirstOrDefaultAsync(c => c.Id == req.ClientId, ct);
        if (client is null) return Results.BadRequest("clientId not found");

        var row = new Project
        {
            ClientId = req.ClientId,
            Name = name,
            Description = string.IsNullOrWhiteSpace(req.Description) ? null : req.Description.Trim(),
        };
        db.Projects.Add(row);
        try { await db.SaveChangesAsync(ct); }
        catch (DbUpdateException) { return Results.Conflict("project name already exists under this client"); }

        return Results.Created($"/projects/{row.Id}",
            new ProjectListItem(row.Id, row.Name, row.ClientId, client.Name, 0));
    }

    private static async Task<IResult> CreateComponentAsync(
        CreateComponentRequest req, HttpContext ctx, FindingsDbContext db, CancellationToken ct)
    {
        var (_, deny) = await RequireAdminAsync(ctx, db, ct);
        if (deny is not null) return deny;
        var name = req.Name?.Trim();
        if (string.IsNullOrWhiteSpace(name)) return Results.BadRequest("name required");

        var project = await db.Projects.AsNoTracking()
            .Include(p => p.Client)
            .FirstOrDefaultAsync(p => p.Id == req.ProjectId, ct);
        if (project is null) return Results.BadRequest("projectId not found");

        var row = new Component
        {
            ProjectId = req.ProjectId,
            Name = name,
            Kind = string.IsNullOrWhiteSpace(req.Kind) ? null : req.Kind.Trim(),
        };
        db.Components.Add(row);
        try { await db.SaveChangesAsync(ct); }
        catch (DbUpdateException) { return Results.Conflict("component name already exists under this project"); }

        return Results.Created($"/components/{row.Id}",
            new ComponentListItem(
                row.Id, row.Name, row.Kind,
                row.ProjectId, project.Name,
                project.ClientId, project.Client?.Name ?? "",
                0));
    }

    private static async Task<(User? user, IResult? deny)> RequireAdminAsync(HttpContext ctx, FindingsDbContext db, CancellationToken ct)
    {
        if (!Guid.TryParse(ctx.User.FindFirstValue(AuthExtensions.TampUserIdClaim), out var uid))
            return (null, Results.Unauthorized());
        var user = await db.Users.FirstOrDefaultAsync(u => u.Id == uid, ct);
        if (user is null || !user.IsApproved) return (null, Results.Unauthorized());
        if (!user.IsAdmin) return (user, Results.Forbid());
        return (user, null);
    }
}
