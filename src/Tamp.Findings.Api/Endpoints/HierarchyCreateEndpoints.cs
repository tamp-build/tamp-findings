using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Api.Contracts;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Projects;
using Tamp.Findings.Data;

namespace Tamp.Findings.Api.Endpoints;

// Create-side counterparts to the GET /clients|/projects list endpoints in
// FindingsListEndpoints.
//
// These used to add the rows themselves after an inline IsAdmin check, which
// left two problems (TFND-258):
//
//  - No audit entry. HierarchyService records `client.created` and
//    `project.created`; this path recorded nothing, so creating a tenant over
//    HTTP left no trace while the same act through the UI did. Creating a tenant
//    is exactly the structural change an assessor looks for in the log.
//
//  - A different authorization rule. The inline check demanded IsAdmin for a
//    PROJECT, while HierarchyService asks for Capability.CreateProject, which an
//    Architect holds. So an Architect could create a project in the app and not
//    over the API, for no reason anybody chose.
//
// Both are fixed by delegating. The services own the rules and the audit rows,
// and these endpoints are now only transport: resolve the cookie user to a
// Principal at the right scope, hand off, translate the Result into a status.
public sealed record CreateClientRequest(string Name);
public sealed record CreateProjectRequest(string Name, Guid ClientId, string? Description);

/// <summary>
/// The name the caller must echo to confirm an irreversible cascade (TFND-169).
/// Sent in the body rather than as a query string so it does not end up in an access
/// log or a shell history beside the id it authorises.
/// </summary>
public sealed record DeleteHierarchyRequest(string? ConfirmName);

public static class HierarchyCreateEndpoints
{
    public static IEndpointRouteBuilder MapHierarchyCreate(this IEndpointRouteBuilder app)
    {
        var g = app.MapGroup("").WithTags("Hierarchy");

        g.MapPost("/clients", CreateClientAsync)
         .WithSummary("Create a client. Administrator only — a client sits above every project, so nothing narrower can grant it. Audited.");
        g.MapPost("/projects", CreateProjectAsync)
         .WithSummary("Create a project under a client. Needs the CreateProject capability (Admin or Architect). Audited.");

        g.MapDelete("/projects/{projectId:guid}", DeleteProjectAsync)
         .WithName("DeleteProject")
         .WithSummary("Delete a project and every build, finding, SBOM, coverage report and scan receipt under it. Administrator only. IRREVERSIBLE — the body must echo the project's name exactly. Audited.");
        g.MapDelete("/clients/{clientId:guid}", DeleteClientAsync)
         .WithName("DeleteClient")
         .WithSummary("Delete a client and every project beneath it. Administrator only. IRREVERSIBLE — the body must echo the client's name exactly. Audited.");
        return app;
    }

    private static async Task<IResult> CreateClientAsync(
        CreateClientRequest req, HttpContext ctx, FindingsDbContext db,
        PrincipalResolver principals, HierarchyService hierarchy, CancellationToken ct)
    {
        // Instance scope: there is no narrower place to stand when the thing
        // being created is the top of the tree.
        var (actor, _, deny) = await EndpointActor.ForScopeAsync(
            ctx, db, principals, clientId: null, projectId: null, ct);
        if (deny is not null) return deny;

        var result = await hierarchy.CreateClientAsync(actor!, req.Name ?? "", ct);
        if (result.WasDenied) return Results.Forbid();
        if (!result.Success) return Translate(result.Error);

        var row = await db.Clients.AsNoTracking()
            .Where(c => c.Id == result.Value)
            .Select(c => new ClientListItem(c.Id, c.Name, 0, c.RiskPolicyId))
            .SingleAsync(ct);

        return Results.Created($"/clients/{row.Id}", row);
    }

    private static async Task<IResult> CreateProjectAsync(
        CreateProjectRequest req, HttpContext ctx, FindingsDbContext db,
        PrincipalResolver principals, HierarchyService hierarchy, CancellationToken ct)
    {
        // An unknown clientId is a 400, because it arrived in the BODY: it is a
        // bad field in a submitted request, not a missing resource at the URL.
        // Checked here rather than letting ForScopeAsync answer, because that
        // helper is built for path-addressed resources and 404s — and changing
        // a documented status code as a side effect of an internal refactor
        // would break a caller for no reason anybody chose.
        if (!await db.Clients.AsNoTracking().AnyAsync(c => c.Id == req.ClientId, ct))
            return Results.BadRequest("clientId not found");

        // Scoped to the client the project will sit under, so the capability is
        // evaluated where it actually applies.
        var (actor, _, deny) = await EndpointActor.ForScopeAsync(
            ctx, db, principals, clientId: req.ClientId, projectId: null, ct);
        if (deny is not null) return deny;

        var result = await hierarchy.CreateProjectAsync(
            actor!, req.ClientId, req.Name ?? "", req.Description, ct);
        if (result.WasDenied) return Results.Forbid();
        if (!result.Success) return Translate(result.Error);

        var row = await db.Projects.AsNoTracking()
            .Where(pr => pr.Id == result.Value)
            .Select(pr => new ProjectListItem(pr.Id, pr.Name, pr.ClientId, pr.Client!.Name, 0))
            .SingleAsync(ct);

        return Results.Created($"/projects/{row.Id}", row);
    }

    // Delete is addressed by PATH, so an id that does not exist is a 404 — unlike the
    // unknown clientId above, which arrives in a body and is therefore a bad field.
    // The existence check is here rather than in the service because the service speaks
    // Result, which distinguishes "you may not" from "that does not work" but has no
    // way to say "there is nothing at this URL".
    private static async Task<IResult> DeleteProjectAsync(
        Guid projectId, [FromBody] DeleteHierarchyRequest? req, HttpContext ctx, FindingsDbContext db,
        PrincipalResolver principals, HierarchyService hierarchy, CancellationToken ct)
    {
        var owner = await db.Projects.AsNoTracking()
            .Where(p => p.Id == projectId)
            .Select(p => new { p.ClientId })
            .FirstOrDefaultAsync(ct);
        if (owner is null) return Results.NotFound("project not found");

        var (actor, _, deny) = await EndpointActor.ForScopeAsync(
            ctx, db, principals, owner.ClientId, projectId, ct);
        if (deny is not null) return deny;

        var result = await hierarchy.DeleteProjectAsync(actor!, projectId, req?.ConfirmName, ct);
        if (result.WasDenied) return Results.Forbid();
        if (!result.Success) return Results.BadRequest(result.Error);

        // The counts come back rather than a bare 204: an operator who has just run an
        // irreversible cascade should be told what went, and a 204 cannot say.
        return Results.Ok(result.Value);
    }

    private static async Task<IResult> DeleteClientAsync(
        Guid clientId, [FromBody] DeleteHierarchyRequest? req, HttpContext ctx, FindingsDbContext db,
        PrincipalResolver principals, HierarchyService hierarchy, CancellationToken ct)
    {
        if (!await db.Clients.AsNoTracking().AnyAsync(c => c.Id == clientId, ct))
            return Results.NotFound("client not found");

        var (actor, _, deny) = await EndpointActor.ForScopeAsync(
            ctx, db, principals, clientId, projectId: null, ct);
        if (deny is not null) return deny;

        var result = await hierarchy.DeleteClientAsync(actor!, clientId, req?.ConfirmName, ct);
        if (result.WasDenied) return Results.Forbid();
        if (!result.Success) return Results.BadRequest(result.Error);

        return Results.Ok(result.Value);
    }

    // The service reports "already exists" as an invalid result rather than an
    // exception, so the duplicate case has to be recognised to keep answering
    // 409 — a client retrying a create wants to tell "you already have one"
    // apart from "your request was malformed".
    private static IResult Translate(string? error) =>
        error is { Length: > 0 } message && message.Contains("already", StringComparison.OrdinalIgnoreCase)
            ? Results.Conflict(message)
            : Results.BadRequest(error ?? "could not create");
}
