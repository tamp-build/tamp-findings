using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Application.Authorization;

/// <summary>
/// Turns a user plus their role assignments into the <see cref="Principal"/>
/// that holds at a given target.
///
/// <para>
/// The hand-off states two rules that pull against each other, and reconciling
/// them is the whole job of this class:
/// </para>
/// <list type="bullet">
///   <item>"Roles are additive. A user holds any number of them and effective
///   access is the union."</item>
///   <item>"Assignments are scoped to client, project or component, and the
///   narrower grant wins where they overlap."</item>
/// </list>
///
/// <para>
/// Taken naively, a user who is InfoSec at the client and Lead Dev on one
/// component is either both (union) or only Lead Dev (narrower wins) at that
/// component. TFND-3 / F2.2 settles it: "Role assignments set at Client,
/// overridable at Project, overridable at Component", and "inherits from higher
/// tier unless explicitly overridden at the lower tier."
/// </para>
///
/// <para>
/// So: <b>the narrowest tier carrying ANY assignment for that user wins
/// entirely, and roles are unioned within that tier.</b> Additive applies
/// across roles at the same tier; override applies across tiers.
/// </para>
///
/// <para>
/// The consequence is deliberate and worth stating plainly: granting someone a
/// narrow role can REMOVE access they had from a broader one. Making an
/// organisation-wide InfoSec Officer a Lead Dev on one component demotes them
/// on that component. That is what "overridable" means, and it is the only
/// reading under which a narrow grant can express "here, this person is only
/// this" — which is the point of having tiers at all.
/// </para>
/// </summary>
public sealed class ScopeResolver
{
    /// <summary>
    /// Build the principal that holds at <paramref name="target"/>.
    /// </summary>
    /// <param name="assignments">
    /// The user's assignments. May include ones that do not cover the target;
    /// they are filtered here so callers can pass a user's full set and let
    /// this decide what applies.
    /// </param>
    public Principal Resolve(
        Guid userId,
        string login,
        bool isAdmin,
        IEnumerable<ProjectRoleAssignment> assignments,
        ScopeTarget target)
    {
        ArgumentNullException.ThrowIfNull(assignments);

        var covering = assignments
            .Where(a => a.UserId == userId && Covers(a, target))
            .ToArray();

        // Narrowest tier that has anything to say. An assignment at the
        // component tier silences the project and client tiers; a project
        // assignment silences the client tier.
        var roles = Array.Empty<ProjectRole>();
        if (covering.Length > 0)
        {
            var narrowest = covering.Max(TierOf);
            roles = covering
                .Where(a => TierOf(a) == narrowest)
                .Select(a => a.Role)
                .Distinct()
                .ToArray();
        }

        return Principal.For(userId, login, isAdmin, roles);
    }

    /// <summary>
    /// Does this assignment reach the target?
    ///
    /// An assignment covers a target when every tier the assignment names
    /// matches the target's. A client-tier assignment covers every project and
    /// component beneath it; a component-tier assignment covers only that
    /// component and does NOT cover its project.
    /// </summary>
    private static bool Covers(ProjectRoleAssignment a, ScopeTarget target)
    {
        if (a.ComponentId is not null) return a.ComponentId == target.ComponentId;
        if (a.ProjectId is not null) return a.ProjectId == target.ProjectId;
        if (a.ClientId is not null) return a.ClientId == target.ClientId;

        // An assignment naming no tier at all is malformed — every
        // ProjectRoleAssignment is scoped to at least a client. Treating it as
        // covering everything would turn a data defect into instance-wide
        // access, so it covers nothing.
        return false;
    }

    private static int TierOf(ProjectRoleAssignment a) =>
        a.ComponentId is not null ? 3 : a.ProjectId is not null ? 2 : 1;
}
