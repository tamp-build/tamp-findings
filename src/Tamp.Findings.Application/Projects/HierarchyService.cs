using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Application.Auditing;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Application.Projects;

/// <summary>
/// Creating clients and projects.
///
/// The hand-off lists the create-hierarchy flow as NOT COVERED, yet renders
/// "New client" and "New project" on the portfolio header — buttons with no
/// destination. This is that gap (TFND-85).
///
/// The hierarchy is load-bearing: Client &gt; Project &gt; Component &gt; Build
/// appears on nearly every screen, drives scope resolution and therefore
/// authorization, and cannot be reshaped later without touching all of it.
/// Getting a name wrong here is cheap; getting the shape wrong is not.
/// </summary>
public sealed class HierarchyService
{
    private readonly FindingsDbContext _db;
    private readonly CapabilityEvaluator _capabilities;
    private readonly AuditLog _audit;

    public HierarchyService(FindingsDbContext db, CapabilityEvaluator capabilities, AuditLog audit)
    {
        _db = db;
        _capabilities = capabilities;
        _audit = audit;
    }

    public async Task<IReadOnlyList<ClientRow>> ClientsAsync(CancellationToken ct = default) =>
        await _db.Clients.AsNoTracking()
            .OrderBy(c => c.Name)
            .Select(c => new ClientRow(c.Id, c.Name))
            .ToArrayAsync(ct);

    /// <summary>
    /// Creating a client is Admin-only. It is the top of the hierarchy and
    /// every scope beneath it inherits from it, so it is closer to an instance
    /// operation than a project one.
    /// </summary>
    public async Task<Result<Guid>> CreateClientAsync(
        Principal actor, string name, CancellationToken ct = default)
    {
        if (!actor.Actors.Contains(Actor.Admin))
        {
            return Result<Guid>.Denied(
                "Creating a client is an instance-level action and requires an administrator.");
        }

        name = name.Trim();
        if (name.Length == 0) return Result<Guid>.Invalid("A client needs a name.");

        if (await _db.Clients.AnyAsync(c => c.Name.ToLower() == name.ToLower(), ct))
            return Result<Guid>.Invalid($"A client called \"{name}\" already exists.");

        var client = new Client { Name = name };
        _db.Clients.Add(client);

        _audit.Record(actor, "client.created", AuditClass.Other, ScopeTarget.Client(client.Id),
            subjectId: client.Id, subjectKind: nameof(Client), detail: name);

        await _db.SaveChangesAsync(ct);
        return Result<Guid>.Ok(client.Id);
    }

    public async Task<Result<Guid>> CreateProjectAsync(
        Principal actor, Guid clientId, string name, string? description, CancellationToken ct = default)
    {
        var decision = _capabilities.Evaluate(actor, Capability.CreateProject);
        if (!decision.Allowed) return Result<Guid>.Denied(decision.Reason!);

        name = name.Trim();
        if (name.Length == 0) return Result<Guid>.Invalid("A project needs a name.");

        if (!await _db.Clients.AnyAsync(c => c.Id == clientId, ct))
            return Result<Guid>.Invalid("That client no longer exists.");

        // Names are unique per client rather than globally: the URL scheme is
        // /c/{client}/p/{project}, so two clients may each have a "tamp"
        // without ambiguity, and forbidding that would be an arbitrary
        // restriction on a multi-tenant install.
        if (await _db.Projects.AnyAsync(p => p.ClientId == clientId && p.Name.ToLower() == name.ToLower(), ct))
            return Result<Guid>.Invalid($"This client already has a project called \"{name}\".");

        // Trim and blank-normalise, the same treatment Name gets two lines up.
        // The HTTP endpoint used to do this itself; when it was folded into this
        // service (TFND-258) that normalisation would have been lost, so it
        // lives here now and both callers get it. A description of "   " is an
        // absent description, not a description made of spaces.
        description = string.IsNullOrWhiteSpace(description) ? null : description.Trim();

        var project = new Project { ClientId = clientId, Name = name, Description = description };
        _db.Projects.Add(project);

        _audit.Record(actor, "project.created", AuditClass.Other,
            ScopeTarget.Project(clientId, project.Id),
            subjectId: project.Id, subjectKind: nameof(Project), detail: name);

        await _db.SaveChangesAsync(ct);
        return Result<Guid>.Ok(project.Id);
    }

    // ---- removing hierarchy (TFND-169) -------------------------------------
    //
    // There was no application path to delete any of this. Clearing one stale,
    // misnamed project meant a raw cascade DELETE against the lab's Postgres over
    // kubectl — which is not something an operator can do, leaves no audit row, and
    // is the most destructive operation in the product performed by the least
    // supervised route.
    //
    // Three deliberate choices:
    //
    //  - Admin only, for projects as well as clients. CreateProject is delegable to a
    //    project-scoped role through Capability.CreateProject, and reusing that here
    //    would let whoever may create a project destroy its entire evidence history.
    //    Creating hierarchy and erasing it are not the same authority.
    //
    //  - The name echo is enforced HERE, not just in the dialog. A guard that lives in
    //    the SPA guards the SPA; this endpoint is reachable by curl and by anything
    //    holding an admin session, and an irreversible cascade deserves the same
    //    confirmation whichever door it comes through.
    //
    //  - It reports what it destroyed. The counts are read before the delete so the
    //    audit detail and the operator's confirmation say "14 builds, 212 findings"
    //    rather than "ok" — the difference between a record and a receipt.
    //
    // The audit row survives its own subject: AuditEntry.ClientId / ProjectId are
    // plain Guids with an index and no foreign key, so nothing cascades them away, and
    // SaveChanges rejects any attempt to modify or delete one.

    /// <summary>
    /// Delete a project and everything hanging off it. Admin only; the caller must echo
    /// the project's name exactly. Irreversible — the FK graph cascades from here down
    /// through builds to findings, SBOMs, coverage and scan receipts.
    /// </summary>
    public async Task<Result<HierarchyRemoval>> DeleteProjectAsync(
        Principal actor, Guid projectId, string? confirmName, CancellationToken ct = default)
    {
        if (!actor.Actors.Contains(Actor.Admin))
        {
            return Result<HierarchyRemoval>.Denied(
                "Deleting a project destroys its entire evidence history and requires an administrator.");
        }

        var project = await _db.Projects.FirstOrDefaultAsync(p => p.Id == projectId, ct);
        if (project is null) return Result<HierarchyRemoval>.Invalid("That project no longer exists.");

        if (!NameEchoed(confirmName, project.Name))
        {
            return Result<HierarchyRemoval>.Invalid(
                $"To confirm, type the project's name exactly: \"{project.Name}\".");
        }

        var removal = new HierarchyRemoval(
            project.Name,
            Projects: 1,
            Builds: await _db.ComponentVersions.CountAsync(v => v.ProjectId == projectId, ct),
            Findings: await _db.Findings.CountAsync(f => f.ComponentVersion!.ProjectId == projectId, ct));

        _db.Projects.Remove(project);

        _audit.Record(actor, "project.deleted", AuditClass.Other,
            ScopeTarget.Project(project.ClientId, project.Id),
            subjectId: project.Id, subjectKind: nameof(Project), detail: removal.Describe());

        await _db.SaveChangesAsync(ct);
        return Result<HierarchyRemoval>.Ok(removal);
    }

    /// <summary>
    /// Delete a client, every project under it, and everything under those. Admin only;
    /// the caller must echo the client's name exactly.
    /// </summary>
    public async Task<Result<HierarchyRemoval>> DeleteClientAsync(
        Principal actor, Guid clientId, string? confirmName, CancellationToken ct = default)
    {
        if (!actor.Actors.Contains(Actor.Admin))
        {
            return Result<HierarchyRemoval>.Denied(
                "Deleting a client destroys every project beneath it and requires an administrator.");
        }

        var client = await _db.Clients.FirstOrDefaultAsync(c => c.Id == clientId, ct);
        if (client is null) return Result<HierarchyRemoval>.Invalid("That client no longer exists.");

        if (!NameEchoed(confirmName, client.Name))
        {
            return Result<HierarchyRemoval>.Invalid(
                $"To confirm, type the client's name exactly: \"{client.Name}\".");
        }

        var removal = new HierarchyRemoval(
            client.Name,
            Projects: await _db.Projects.CountAsync(p => p.ClientId == clientId, ct),
            Builds: await _db.ComponentVersions.CountAsync(v => v.Project!.ClientId == clientId, ct),
            Findings: await _db.Findings.CountAsync(
                f => f.ComponentVersion!.Project!.ClientId == clientId, ct));

        _db.Clients.Remove(client);

        _audit.Record(actor, "client.deleted", AuditClass.Other, ScopeTarget.Client(client.Id),
            subjectId: client.Id, subjectKind: nameof(Client), detail: removal.Describe());

        await _db.SaveChangesAsync(ct);
        return Result<HierarchyRemoval>.Ok(removal);
    }

    /// <summary>
    /// Exact, ordinal comparison — trimmed only for surrounding whitespace, which a
    /// browser or a shell adds without the operator meaning it. A case-insensitive or
    /// fuzzy match would make the confirmation something you can pass by accident,
    /// which is the one thing it exists to prevent.
    /// </summary>
    private static bool NameEchoed(string? confirmName, string actual) =>
        string.Equals(confirmName?.Trim(), actual, StringComparison.Ordinal);
}

public sealed record ClientRow(Guid Id, string Name);

/// <summary>What a delete destroyed, counted before it happened.</summary>
public sealed record HierarchyRemoval(string Name, int Projects, int Builds, int Findings)
{
    public string Describe() =>
        $"{Name} — {Projects} project(s), {Builds} build(s), {Findings} finding(s)";
}
