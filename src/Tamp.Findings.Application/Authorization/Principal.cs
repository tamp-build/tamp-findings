using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Application.Authorization;

/// <summary>
/// Who is acting, resolved against a target scope.
///
/// Built by scope resolution (TFND-70) from the authenticated user plus their
/// <c>ProjectRoleAssignment</c> rows covering the target. Deliberately NOT
/// constructible from an HTTP header: <c>SuppressionsEndpoints</c> reading
/// <c>X-Author-Role</c> and trusting it is the failure mode this whole layer
/// exists to make unavailable (ADR 0001, TFND-71).
/// </summary>
public sealed class Principal
{
    private Principal(Guid userId, string login, IReadOnlySet<Actor> actors)
    {
        UserId = userId;
        Login = login;
        Actors = actors;
    }

    public Guid UserId { get; }
    public string Login { get; }

    /// <summary>
    /// Every role held at the target scope. Additive — effective access is the
    /// union, never the maximum or the first match.
    /// </summary>
    public IReadOnlySet<Actor> Actors { get; }

    /// <summary>
    /// Build from the instance admin flag and the project roles that cover the
    /// target scope.
    /// </summary>
    public static Principal For(Guid userId, string login, bool isAdmin, IEnumerable<ProjectRole> roles)
    {
        var actors = new HashSet<Actor>();
        if (isAdmin) actors.Add(Actor.Admin);

        foreach (var role in roles)
        {
            actors.Add(role switch
            {
                ProjectRole.InfoSecOfficer => Actor.InfoSecOfficer,
                ProjectRole.LeadDev => Actor.LeadDev,
                ProjectRole.Architect => Actor.Architect,
                ProjectRole.Auditor => Actor.Auditor,
                // Throwing rather than silently mapping to Viewer means a role
                // added later cannot quietly become read-only — a new role
                // that nobody mapped should fail loudly, not grant nothing.
                _ => throw new ArgumentOutOfRangeException(nameof(roles), role, "Unmapped ProjectRole"),
            });
        }

        // Viewer is the implicit default: read access, no role. It is not
        // persisted anywhere — it is the ABSENCE of a grant, which is why it
        // has to be added here rather than looked up.
        if (actors.Count == 0) actors.Add(Actor.Viewer);

        return new Principal(userId, login, actors);
    }

    /// <summary>Someone with read access and no role at all.</summary>
    public static Principal Viewer(Guid userId, string login) =>
        new(userId, login, new HashSet<Actor> { Actor.Viewer });
}
