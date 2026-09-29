using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Application.Authorization;

/// <summary>
/// What a user may READ (TFND-133 / F2.3).
///
/// The capability matrix answers "may this person do that", and every write
/// path asks it. Nothing asked the other question — "may this person SEE that"
/// — so on a multi-client instance any approved user could read every client's
/// findings by navigating to them. The Client tier exists so one instance can
/// hold several tenants, and that shape is the one thing cross-tenant read
/// cannot tolerate.
///
/// One class, resolved once per request, because the alternative is a filter
/// repeated in thirty query methods and forgotten in the thirty-first. Same
/// reasoning as <c>AgentReadService</c> for the MCP surface: the check belongs
/// somewhere a new query cannot route around.
/// </summary>
public sealed class VisibilityScope
{
    private readonly FindingsDbContext _db;

    public VisibilityScope(FindingsDbContext db) => _db = db;

    /// <summary>
    /// Resolve what this user can see.
    /// </summary>
    public async Task<VisibleSet> ForAsync(Guid userId, CancellationToken ct = default)
    {
        var user = await _db.Users.AsNoTracking()
            .Where(u => u.Id == userId)
            .Select(u => new { u.Id, u.IsApproved, u.IsAdmin })
            .SingleOrDefaultAsync(ct);

        // Unapproved is not "read-only", it is "not yet a user of this
        // instance" — the same rule PrincipalResolver applies, and it has to
        // agree with it or somebody awaiting approval reads everything through
        // whichever of the two forgot.
        if (user is null || !user.IsApproved) return VisibleSet.Nothing;

        // Instance admin is instance-wide by definition. There is no scope at
        // which an admin is not an admin.
        if (user.IsAdmin) return VisibleSet.Everything;

        var assignments = await _db.ProjectRoleAssignments.AsNoTracking()
            .Where(a => a.UserId == userId)
            .Select(a => new { a.ClientId, a.ProjectId })
            .ToArrayAsync(ct);

        if (assignments.Length > 0)
        {
            return new VisibleSet(
                Unrestricted: false,
                Clients: assignments
                    .Where(a => a.ProjectId is null && a.ClientId is not null)
                    .Select(a => a.ClientId!.Value).ToHashSet(),
                Projects: assignments
                    .Where(a => a.ProjectId is not null)
                    .Select(a => a.ProjectId!.Value).ToHashSet());
        }

        // No assignments of their own. Whether that means "everything" or
        // "nothing" depends on whether this instance has expressed a visibility
        // policy at all — see Unsegmented below.
        return await UnsegmentedAsync(ct) ? VisibleSet.Everything : VisibleSet.Nothing;
    }

    /// <summary>
    /// Has this instance said anything about who sees what?
    ///
    /// An instance with ZERO role assignments has not expressed a visibility
    /// policy, so approved users see everything and the System panel says so.
    /// The moment the first assignment exists, filtering engages for everyone.
    ///
    /// This is a bootstrap accommodation, the same shape as "the first user
    /// becomes Admin", and it is here rather than in a setting on purpose. The
    /// alternatives are both worse: enforcing strictly would make every
    /// existing instance where nobody assigned roles show an empty portfolio on
    /// the next deploy — which looks exactly like data loss — and a setting
    /// would make a confidentiality control opt-in, which is the
    /// "unscanned gate passes" defect wearing a different hat.
    ///
    /// It self-heals: it stops applying the instant anyone expresses intent,
    /// and it leaves no permanent off-switch behind.
    ///
    /// TFND-157: a multi-tenant instance can opt out of the accommodation with
    /// the StrictVisibility instance setting. When on, the instance is treated
    /// as segmented from day zero — never briefly open before the first grant.
    /// </summary>
    public async Task<bool> UnsegmentedAsync(CancellationToken ct = default)
    {
        var strict = await _db.InstanceSettings.AsNoTracking()
            .Where(s => s.Id == InstanceSettings.SingletonId)
            .Select(s => (bool?)s.StrictVisibility)
            .SingleOrDefaultAsync(ct) ?? false;
        if (strict) return false;

        return !await _db.ProjectRoleAssignments.AsNoTracking().AnyAsync(ct);
    }
}

/// <summary>
/// The clients and projects a user may read.
///
/// Expressed as two id sets rather than as a predicate so callers can push
/// the filter into SQL. A predicate would be tidier and would drag every
/// finding in the instance into memory to evaluate it.
/// </summary>
public sealed record VisibleSet(
    bool Unrestricted,
    IReadOnlySet<Guid> Clients,
    IReadOnlySet<Guid> Projects)
{
    public static VisibleSet Everything { get; } =
        new(true, new HashSet<Guid>(), new HashSet<Guid>());

    /// <summary>
    /// Sees nothing. NOT the same as <see cref="Everything"/> with empty sets,
    /// which is why <c>Unrestricted</c> is a flag rather than inferred from the
    /// sets being empty — inferring it would make "no grants" mean "no limits",
    /// and that is the failure this whole class exists to prevent.
    /// </summary>
    public static VisibleSet Nothing { get; } =
        new(false, new HashSet<Guid>(), new HashSet<Guid>());

    /// <summary>True when this set can reach nothing at all.</summary>
    public bool IsEmpty =>
        !Unrestricted && Clients.Count == 0 && Projects.Count == 0;

    public bool CanSeeClient(Guid clientId) => Unrestricted || Clients.Contains(clientId);

    /// <summary>A project is visible through its own grant, or through its client's.</summary>
    public bool CanSeeProject(Guid clientId, Guid projectId) =>
        Unrestricted || Clients.Contains(clientId) || Projects.Contains(projectId);
}
