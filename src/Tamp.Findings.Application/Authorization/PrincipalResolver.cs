using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Data;

namespace Tamp.Findings.Application.Authorization;

/// <summary>
/// Loads a user's role assignments and resolves the principal that holds at a
/// target.
///
/// This is the only supported way to obtain a <see cref="Principal"/> for a
/// real request. It reads the user's admin flag from the DATABASE rather than
/// from a claim or a header, so a stale cookie cannot carry an admin flag that
/// has since been revoked, and nothing a client sends can influence the answer.
/// </summary>
public sealed class PrincipalResolver
{
    private readonly FindingsDbContext _db;
    private readonly ScopeResolver _scopes;

    public PrincipalResolver(FindingsDbContext db, ScopeResolver scopes)
    {
        _db = db;
        _scopes = scopes;
    }

    /// <summary>
    /// Resolve by user id — the id carried on the authenticated cookie.
    /// Returns null when the user does not exist or is not approved, which the
    /// caller must treat as a denial rather than as a Viewer.
    /// </summary>
    public async Task<Principal?> ResolveAsync(Guid userId, ScopeTarget target, CancellationToken ct = default)
    {
        var user = await _db.Users.AsNoTracking().FirstOrDefaultAsync(u => u.Id == userId, ct);

        // Unapproved is not "read-only" — it is "not yet a user of this
        // instance". Falling through to Viewer here would let anyone who has
        // signed in once read everything while awaiting approval.
        if (user is null || !user.IsApproved) return null;

        var assignments = await _db.ProjectRoleAssignments
            .AsNoTracking()
            .Where(a => a.UserId == userId)
            .ToArrayAsync(ct);

        return _scopes.Resolve(user.Id, user.Login, user.IsAdmin, assignments, target);
    }

    /// <summary>
    /// Walk a component up to its project and client so scope resolution has
    /// the full chain. Returns null when the component does not exist.
    /// </summary>
    public async Task<ScopeTarget?> TargetForComponentAsync(Guid componentId, CancellationToken ct = default)
    {
        var row = await (
            from c in _db.Components.AsNoTracking()
            join p in _db.Projects.AsNoTracking() on c.ProjectId equals p.Id
            where c.Id == componentId
            select new { c.Id, p.ClientId, ProjectId = p.Id }).FirstOrDefaultAsync(ct);

        return row is null ? null : ScopeTarget.Component(row.ClientId, row.ProjectId, row.Id);
    }

    /// <summary>Walk a project up to its client.</summary>
    public async Task<ScopeTarget?> TargetForProjectAsync(Guid projectId, CancellationToken ct = default)
    {
        var row = await _db.Projects.AsNoTracking()
            .Where(p => p.Id == projectId)
            .Select(p => new { p.Id, p.ClientId })
            .FirstOrDefaultAsync(ct);

        return row is null ? null : ScopeTarget.Project(row.ClientId, row.Id);
    }
}
