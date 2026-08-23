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

        var project = new Project { ClientId = clientId, Name = name, Description = description };
        _db.Projects.Add(project);

        _audit.Record(actor, "project.created", AuditClass.Other,
            ScopeTarget.Project(clientId, project.Id),
            subjectId: project.Id, subjectKind: nameof(Project), detail: name);

        await _db.SaveChangesAsync(ct);
        return Result<Guid>.Ok(project.Id);
    }
}

public sealed record ClientRow(Guid Id, string Name);
