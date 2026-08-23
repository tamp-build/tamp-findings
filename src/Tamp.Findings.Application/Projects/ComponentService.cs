using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Application.Auditing;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Application.Projects;

/// <summary>
/// Reading and changing a project's components.
///
/// A component is one deployable unit; the same commit can produce several
/// builds distinguished by flavor (net10, web, deployed). That distinction is
/// load-bearing — flattening flavors into components would make "which build
/// shipped" unanswerable.
///
/// Every mutation checks the capability HERE rather than trusting the caller,
/// and writes its audit entry in the same transaction. A transport that forgets
/// either is not a vulnerability, because this refuses (ADR 0002).
/// </summary>
public sealed class ComponentService
{
    private readonly FindingsDbContext _db;
    private readonly CapabilityEvaluator _capabilities;
    private readonly AuditLog _audit;

    public ComponentService(FindingsDbContext db, CapabilityEvaluator capabilities, AuditLog audit)
    {
        _db = db;
        _capabilities = capabilities;
        _audit = audit;
    }

    public async Task<IReadOnlyList<ComponentRow>> ListAsync(Guid projectId, CancellationToken ct = default)
    {
        var components = await _db.Components.AsNoTracking()
            .Where(c => c.ProjectId == projectId)
            .OrderBy(c => c.Name)
            .Select(c => new { c.Id, c.Name, c.Kind })
            .ToArrayAsync(ct);

        var ids = components.Select(c => c.Id).ToArray();

        var flavors = await _db.ComponentFlavors.AsNoTracking()
            .Where(f => ids.Contains(f.ComponentId))
            .Select(f => new { f.ComponentId, f.Name })
            .ToArrayAsync(ct);

        var versions = await _db.ComponentVersions.AsNoTracking()
            .Where(v => ids.Contains(v.ComponentId))
            .GroupBy(v => v.ComponentId)
            .Select(g => new { ComponentId = g.Key, Builds = g.Count(), Last = g.Max(v => v.CreatedAt) })
            .ToArrayAsync(ct);

        return components.Select(c => new ComponentRow(
            c.Id,
            c.Name,
            c.Kind,
            flavors.Where(f => f.ComponentId == c.Id).Select(f => f.Name).OrderBy(n => n).ToArray(),
            versions.FirstOrDefault(v => v.ComponentId == c.Id)?.Builds ?? 0,
            versions.FirstOrDefault(v => v.ComponentId == c.Id)?.Last))
            .ToArray();
    }

    public async Task<Result<Guid>> CreateAsync(
        Principal actor, ScopeTarget scope, Guid projectId, string name, string? kind, CancellationToken ct = default)
    {
        var decision = _capabilities.Evaluate(actor, Capability.CreateComponent);
        if (!decision.Allowed) return Result<Guid>.Denied(decision.Reason!);

        name = name.Trim();
        if (name.Length == 0) return Result<Guid>.Invalid("A component needs a name.");

        var clash = await _db.Components.AnyAsync(
            c => c.ProjectId == projectId && c.Name.ToLower() == name.ToLower(), ct);
        if (clash) return Result<Guid>.Invalid($"This project already has a component called \"{name}\".");

        var component = new Component { ProjectId = projectId, Name = name, Kind = kind };
        _db.Components.Add(component);

        _audit.Record(actor, "component.created", AuditClass.Other, scope,
            subjectId: component.Id, subjectKind: nameof(Component), detail: name);

        await _db.SaveChangesAsync(ct);
        return Result<Guid>.Ok(component.Id);
    }

    /// <summary>
    /// Delete a component and everything ingested against it.
    ///
    /// Refuses when the component has builds. That is deliberate and not
    /// merely cautious: those builds are the evidence behind past attestations,
    /// and "a deleted item leaves no audit trail" applies to evidence at least
    /// as strongly as to POA&amp;M items. Renaming or abandoning a component is
    /// the non-destructive path.
    /// </summary>
    public async Task<Result<bool>> DeleteAsync(
        Principal actor, ScopeTarget scope, Guid componentId, CancellationToken ct = default)
    {
        var decision = _capabilities.Evaluate(actor, Capability.CreateComponent);
        if (!decision.Allowed) return Result<bool>.Denied(decision.Reason!);

        var component = await _db.Components.FirstOrDefaultAsync(c => c.Id == componentId, ct);
        if (component is null) return Result<bool>.Invalid("That component no longer exists.");

        var builds = await _db.ComponentVersions.CountAsync(v => v.ComponentId == componentId, ct);
        if (builds > 0)
        {
            return Result<bool>.Invalid(
                $"\"{component.Name}\" has {builds} ingested build{(builds == 1 ? "" : "s")}. "
                + "Those builds are the evidence behind any attestation that cited them, so the "
                + "component cannot be deleted. Stop ingesting to it instead.");
        }

        _db.Components.Remove(component);
        _audit.Record(actor, "component.deleted", AuditClass.Other, scope,
            subjectId: componentId, subjectKind: nameof(Component), detail: component.Name);

        await _db.SaveChangesAsync(ct);
        return Result<bool>.Ok(true);
    }
}

public sealed record ComponentRow(
    Guid Id,
    string Name,
    string? Kind,
    IReadOnlyList<string> Flavors,
    int Builds,
    DateTimeOffset? LastBuild);

/// <summary>
/// The outcome of a command, distinguishing "you may not" from "that does not
/// work".
///
/// They read differently to the user and belong in different places: a denial
/// is a disabled control with a reason, an invalid input is a message beside
/// the field. Collapsing them into one bool loses that.
/// </summary>
public sealed record Result<T>(bool Success, T? Value, string? Error, bool WasDenied)
{
    public static Result<T> Ok(T value) => new(true, value, null, false);
    public static Result<T> Denied(string reason) => new(false, default, reason, true);
    public static Result<T> Invalid(string message) => new(false, default, message, false);
}
