using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Api.Authentication;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Risk;

namespace Tamp.Findings.Api.Endpoints;

// DTOs --------------------------------------------------------------------

public sealed record RiskPolicySummary(
    Guid Id, string Name, string? Description, bool IsDefault, bool IsSeeded,
    DateTimeOffset CreatedAt, DateTimeOffset UpdatedAt);

public sealed record RiskPolicyFull(
    Guid Id, string Name, string? Description, bool IsDefault, bool IsSeeded,
    RiskPolicyConfig Config,
    DateTimeOffset CreatedAt, DateTimeOffset UpdatedAt);

public sealed record CreateRiskPolicyRequest(string Name, string? Description, RiskPolicyConfig Config);
public sealed record UpdateRiskPolicyRequest(string? Name, string? Description, RiskPolicyConfig? Config);
public sealed record ClonePolicyRequest(string Name);
public sealed record AssignPolicyRequest(Guid? PolicyId);

// Project-scoped read shape: inherited policy resolution plus the
// effective policy id/name so the SPA can render "(inherited from
// <name>)" without a second round-trip.
public sealed record ProjectPolicyAndGatesView(
    Guid? AssignedPolicyId,           // null when inheriting
    Guid EffectivePolicyId,           // resolved (project ?? client ?? default)
    string EffectivePolicyName,
    bool EffectiveFromProject,
    bool EffectiveFromClient,
    ProjectGatesConfig Gates);

public sealed record UpdateGatesRequest(ProjectGatesConfig Gates);

// --------------------------------------------------------------------------

public static class RiskPolicyEndpoints
{
    public static IEndpointRouteBuilder MapRiskPolicies(this IEndpointRouteBuilder app)
    {
        var g = app.MapGroup("").WithTags("RiskPolicies");

        g.MapGet("/risk-policies", ListAsync)
         .WithSummary("List all risk policies (metadata only). Anyone with a session can read this so the SPA can populate the selector.");
        g.MapGet("/risk-policies/{id:guid}", GetAsync)
         .WithSummary("Full policy including the config blob.");

        // Admin-gated mutations.
        g.MapPost("/risk-policies", CreateAsync)
         .WithSummary("Create a new policy from scratch. Admin only.");
        g.MapPost("/risk-policies/{id:guid}/clone", CloneAsync)
         .WithSummary("Clone an existing policy under a new name (handy starting point for customising the seed). Admin only.");
        g.MapPatch("/risk-policies/{id:guid}", UpdateAsync)
         .WithSummary("Edit a policy in place. Admin only.");
        g.MapDelete("/risk-policies/{id:guid}", DeleteAsync)
         .WithSummary("Delete a policy. Cannot delete the default. Admin only. Any client/project pointing at the deleted policy falls back to default (FK SetNull).");
        g.MapPost("/risk-policies/{id:guid}/set-default", SetDefaultAsync)
         .WithSummary("Make this policy the system default. Atomically clears the previous default. Admin only.");

        // Scope assignment.
        g.MapPatch("/clients/{clientId:guid}/policy", AssignClientAsync)
         .WithSummary("Set or clear the risk policy on a client. Admin only (project-owner check lands with TFND-3).");
        g.MapPatch("/projects/{projectId:guid}/policy", AssignProjectAsync)
         .WithSummary("Set or clear the risk policy on a project.");
        g.MapGet("/projects/{projectId:guid}/policy-and-gates", GetProjectPolicyAndGatesAsync)
         .WithSummary("Project policy assignment + effective policy + gates config — one round-trip for the Project Settings dialog.");
        g.MapPost("/projects/{projectId:guid}/policy/fork", ForkProjectPolicyAsync)
         .WithSummary("Clone the project's current effective policy into a new RiskPolicy and assign it to the project. Used by the 'Override' button when disconnecting from the inherited policy.");
        g.MapPatch("/projects/{projectId:guid}/gates", UpdateProjectGatesAsync)
         .WithSummary("Replace the per-project gates config.");

        return app;
    }

    // ---- Read paths (anyone authenticated) ------------------------------

    private static async Task<Ok<IReadOnlyList<RiskPolicySummary>>> ListAsync(FindingsDbContext db, CancellationToken ct)
    {
        var rows = await db.RiskPolicies.AsNoTracking()
            .OrderByDescending(p => p.IsDefault).ThenBy(p => p.Name)
            .Select(p => new RiskPolicySummary(
                p.Id, p.Name, p.Description, p.IsDefault, p.IsSeeded,
                p.CreatedAt, p.UpdatedAt))
            .ToListAsync(ct);
        return TypedResults.Ok((IReadOnlyList<RiskPolicySummary>)rows);
    }

    private static async Task<IResult> GetAsync(Guid id, FindingsDbContext db, CancellationToken ct)
    {
        var p = await db.RiskPolicies.AsNoTracking().FirstOrDefaultAsync(x => x.Id == id, ct);
        if (p is null) return Results.NotFound();
        return Results.Ok(new RiskPolicyFull(
            p.Id, p.Name, p.Description, p.IsDefault, p.IsSeeded,
            p.Config, p.CreatedAt, p.UpdatedAt));
    }

    // ---- Write paths (admin gate) ---------------------------------------

    private static async Task<IResult> CreateAsync(CreateRiskPolicyRequest req, HttpContext ctx, FindingsDbContext db, CancellationToken ct)
    {
        var (user, deny) = await RequireAdminAsync(ctx, db, ct);
        if (deny is not null) return deny;
        if (string.IsNullOrWhiteSpace(req.Name)) return Results.BadRequest("name required");
        if (req.Config is null || req.Config.SchemaVersion < 1) return Results.BadRequest("config invalid");

        var p = new RiskPolicy
        {
            Name = req.Name.Trim(),
            Description = req.Description,
            Config = req.Config,
            CreatedByUserId = user!.Id,
        };
        db.RiskPolicies.Add(p);
        try { await db.SaveChangesAsync(ct); }
        catch (DbUpdateException) { return Results.Conflict("policy name already exists"); }

        return Results.Created($"/risk-policies/{p.Id}", new RiskPolicyFull(
            p.Id, p.Name, p.Description, p.IsDefault, p.IsSeeded, p.Config, p.CreatedAt, p.UpdatedAt));
    }

    private static async Task<IResult> CloneAsync(Guid id, ClonePolicyRequest req, HttpContext ctx, FindingsDbContext db, CancellationToken ct)
    {
        var (user, deny) = await RequireAdminAsync(ctx, db, ct);
        if (deny is not null) return deny;
        if (string.IsNullOrWhiteSpace(req.Name)) return Results.BadRequest("name required");

        var src = await db.RiskPolicies.AsNoTracking().FirstOrDefaultAsync(p => p.Id == id, ct);
        if (src is null) return Results.NotFound();

        var clone = new RiskPolicy
        {
            Name = req.Name.Trim(),
            Description = src.Description,
            Config = src.Config,
            CreatedByUserId = user!.Id,
        };
        db.RiskPolicies.Add(clone);
        try { await db.SaveChangesAsync(ct); }
        catch (DbUpdateException) { return Results.Conflict("policy name already exists"); }

        return Results.Created($"/risk-policies/{clone.Id}", new RiskPolicyFull(
            clone.Id, clone.Name, clone.Description, clone.IsDefault, clone.IsSeeded,
            clone.Config, clone.CreatedAt, clone.UpdatedAt));
    }

    private static async Task<IResult> UpdateAsync(Guid id, UpdateRiskPolicyRequest req, HttpContext ctx, FindingsDbContext db, CancellationToken ct)
    {
        var (_, deny) = await RequireAdminAsync(ctx, db, ct);
        if (deny is not null) return deny;

        var p = await db.RiskPolicies.FirstOrDefaultAsync(x => x.Id == id, ct);
        if (p is null) return Results.NotFound();

        if (req.Name is { } n && !string.IsNullOrWhiteSpace(n)) p.Name = n.Trim();
        if (req.Description is not null) p.Description = string.IsNullOrWhiteSpace(req.Description) ? null : req.Description;
        if (req.Config is not null)
        {
            if (req.Config.SchemaVersion < 1) return Results.BadRequest("config schemaVersion invalid");
            p.Config = req.Config;
        }
        p.UpdatedAt = DateTimeOffset.UtcNow;

        try { await db.SaveChangesAsync(ct); }
        catch (DbUpdateException) { return Results.Conflict("policy name conflict"); }
        return Results.Ok(new RiskPolicyFull(p.Id, p.Name, p.Description, p.IsDefault, p.IsSeeded, p.Config, p.CreatedAt, p.UpdatedAt));
    }

    private static async Task<IResult> DeleteAsync(Guid id, HttpContext ctx, FindingsDbContext db, CancellationToken ct)
    {
        var (_, deny) = await RequireAdminAsync(ctx, db, ct);
        if (deny is not null) return deny;
        var p = await db.RiskPolicies.FirstOrDefaultAsync(x => x.Id == id, ct);
        if (p is null) return Results.NotFound();
        if (p.IsDefault) return Results.Conflict("cannot delete the default policy; set another default first");
        db.RiskPolicies.Remove(p);
        await db.SaveChangesAsync(ct);
        return Results.NoContent();
    }

    private static async Task<IResult> SetDefaultAsync(Guid id, HttpContext ctx, FindingsDbContext db, CancellationToken ct)
    {
        var (_, deny) = await RequireAdminAsync(ctx, db, ct);
        if (deny is not null) return deny;
        // Two-step inside a transaction so we never end up with zero
        // defaults if the second update fails.
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        var target = await db.RiskPolicies.FirstOrDefaultAsync(x => x.Id == id, ct);
        if (target is null) return Results.NotFound();
        var prior = await db.RiskPolicies.Where(p => p.IsDefault && p.Id != id).ToListAsync(ct);
        foreach (var p in prior) p.IsDefault = false;
        target.IsDefault = true;
        target.UpdatedAt = DateTimeOffset.UtcNow;
        await db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);
        return Results.NoContent();
    }

    private static async Task<IResult> AssignClientAsync(Guid clientId, AssignPolicyRequest req, HttpContext ctx, FindingsDbContext db, CancellationToken ct)
    {
        var (_, deny) = await RequireAdminAsync(ctx, db, ct);
        if (deny is not null) return deny;
        var client = await db.Clients.FirstOrDefaultAsync(c => c.Id == clientId, ct);
        if (client is null) return Results.NotFound("client not found");
        if (req.PolicyId is { } pid)
        {
            var exists = await db.RiskPolicies.AnyAsync(p => p.Id == pid, ct);
            if (!exists) return Results.BadRequest("policy not found");
        }
        client.RiskPolicyId = req.PolicyId;
        await db.SaveChangesAsync(ct);
        return Results.NoContent();
    }

    private static async Task<IResult> AssignProjectAsync(Guid projectId, AssignPolicyRequest req, HttpContext ctx, FindingsDbContext db, CancellationToken ct)
    {
        var (_, deny) = await RequireAdminAsync(ctx, db, ct);
        if (deny is not null) return deny;
        var project = await db.Projects.FirstOrDefaultAsync(p => p.Id == projectId, ct);
        if (project is null) return Results.NotFound("project not found");
        if (req.PolicyId is { } pid)
        {
            var exists = await db.RiskPolicies.AnyAsync(p => p.Id == pid, ct);
            if (!exists) return Results.BadRequest("policy not found");
        }
        project.RiskPolicyId = req.PolicyId;
        await db.SaveChangesAsync(ct);
        return Results.NoContent();
    }

    private static async Task<IResult> GetProjectPolicyAndGatesAsync(
        Guid projectId, FindingsDbContext db, CancellationToken ct)
    {
        var project = await db.Projects.AsNoTracking()
            .Where(p => p.Id == projectId)
            .Select(p => new
            {
                p.Id, p.RiskPolicyId, p.GatesConfig,
                ClientRiskPolicyId = p.Client!.RiskPolicyId,
            })
            .FirstOrDefaultAsync(ct);
        if (project is null) return Results.NotFound();

        // Resolution: project > client > system default.
        var effectiveId = project.RiskPolicyId ?? project.ClientRiskPolicyId;
        RiskPolicy? effective = null;
        if (effectiveId is { } id)
            effective = await db.RiskPolicies.AsNoTracking().FirstOrDefaultAsync(p => p.Id == id, ct);
        effective ??= await db.RiskPolicies.AsNoTracking().FirstOrDefaultAsync(p => p.IsDefault, ct);
        if (effective is null) return Results.Conflict("no default risk policy exists");

        return Results.Ok(new ProjectPolicyAndGatesView(
            AssignedPolicyId: project.RiskPolicyId,
            EffectivePolicyId: effective.Id,
            EffectivePolicyName: effective.Name,
            EffectiveFromProject: project.RiskPolicyId is not null,
            EffectiveFromClient: project.RiskPolicyId is null && project.ClientRiskPolicyId is not null,
            Gates: project.GatesConfig ?? ProjectGatesDefaults.Empty()));
    }

    private static async Task<IResult> ForkProjectPolicyAsync(
        Guid projectId, HttpContext ctx, FindingsDbContext db, CancellationToken ct)
    {
        var (user, deny) = await RequireAdminAsync(ctx, db, ct);
        if (deny is not null) return deny;

        var project = await db.Projects
            .Include(p => p.Client)
            .FirstOrDefaultAsync(p => p.Id == projectId, ct);
        if (project is null) return Results.NotFound();

        // Resolve the current effective policy — same chain as the
        // scorer uses. Then clone it with a project-scoped name and
        // assign it back to the project.
        var effectiveId = project.RiskPolicyId ?? project.Client?.RiskPolicyId;
        RiskPolicy? source = null;
        if (effectiveId is { } id)
            source = await db.RiskPolicies.AsNoTracking().FirstOrDefaultAsync(p => p.Id == id, ct);
        source ??= await db.RiskPolicies.AsNoTracking().FirstOrDefaultAsync(p => p.IsDefault, ct);
        if (source is null) return Results.Conflict("no default risk policy to fork from");

        // Round-trip through System.Text.Json so the clone owns its own
        // graph (avoids EF tracking the source's Config object twice).
        var configJson = JsonSerializer.Serialize(source.Config);
        var configClone = JsonSerializer.Deserialize<RiskPolicyConfig>(configJson)!;

        var name = $"{project.Client?.Name ?? "project"} / {project.Name} — custom";
        // If a policy with this name already exists (re-fork case), suffix
        // a short timestamp so we never collide on the unique index.
        if (await db.RiskPolicies.AnyAsync(p => p.Name == name, ct))
            name += $" {DateTime.UtcNow:HHmmss}";

        var fork = new RiskPolicy
        {
            Name = name,
            Description = $"Forked from \"{source.Name}\" for {project.Name}.",
            Config = configClone,
            CreatedByUserId = user!.Id,
        };
        db.RiskPolicies.Add(fork);
        project.RiskPolicyId = fork.Id;
        await db.SaveChangesAsync(ct);

        return Results.Ok(new RiskPolicyFull(
            fork.Id, fork.Name, fork.Description, fork.IsDefault, fork.IsSeeded,
            fork.Config, fork.CreatedAt, fork.UpdatedAt));
    }

    private static async Task<IResult> UpdateProjectGatesAsync(
        Guid projectId, UpdateGatesRequest req, HttpContext ctx, FindingsDbContext db, CancellationToken ct)
    {
        var (_, deny) = await RequireAdminAsync(ctx, db, ct);
        if (deny is not null) return deny;
        var project = await db.Projects.FirstOrDefaultAsync(p => p.Id == projectId, ct);
        if (project is null) return Results.NotFound();
        if (req.Gates is null || req.Gates.SchemaVersion < 1) return Results.BadRequest("gates invalid");
        project.GatesConfig = req.Gates;
        await db.SaveChangesAsync(ct);
        return Results.NoContent();
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
