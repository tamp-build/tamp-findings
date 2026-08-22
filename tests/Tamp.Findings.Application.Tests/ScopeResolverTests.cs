using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Application.Tests;

// Scope resolution (TFND-70). Reconciles the hand-off's two rules — roles are
// additive, and the narrower grant wins — which pull against each other.
public class ScopeResolverTests
{
    private readonly ScopeResolver _resolver = new();
    private readonly CapabilityEvaluator _evaluator = new();

    private static readonly Guid User = Guid.NewGuid();
    private static readonly Guid ClientA = Guid.NewGuid();
    private static readonly Guid ProjectA = Guid.NewGuid();
    private static readonly Guid ComponentA = Guid.NewGuid();
    private static readonly Guid OtherClient = Guid.NewGuid();
    private static readonly Guid OtherProject = Guid.NewGuid();

    private static ProjectRoleAssignment At(ProjectRole role, Guid? client = null, Guid? project = null, Guid? component = null) =>
        new() { UserId = User, Role = role, ClientId = client, ProjectId = project, ComponentId = component };

    private Principal Resolve(ScopeTarget target, params ProjectRoleAssignment[] assignments) =>
        _resolver.Resolve(User, "test", isAdmin: false, assignments, target);

    // ------------------------------------------------------------------
    // Inheritance
    // ------------------------------------------------------------------

    [Fact]
    public void A_client_level_grant_reaches_every_project_and_component_beneath()
    {
        var assignments = new[] { At(ProjectRole.InfoSecOfficer, client: ClientA) };

        Assert.Contains(Actor.InfoSecOfficer, Resolve(ScopeTarget.Client(ClientA), assignments).Actors);
        Assert.Contains(Actor.InfoSecOfficer, Resolve(ScopeTarget.Project(ClientA, ProjectA), assignments).Actors);
        Assert.Contains(Actor.InfoSecOfficer, Resolve(ScopeTarget.Component(ClientA, ProjectA, ComponentA), assignments).Actors);
    }

    [Fact]
    public void A_grant_does_not_reach_a_sibling_client_or_project()
    {
        var assignments = new[] { At(ProjectRole.InfoSecOfficer, client: ClientA) };

        var elsewhere = Resolve(ScopeTarget.Project(OtherClient, OtherProject), assignments);

        // Falls back to Viewer — read access, no role — rather than carrying
        // the grant sideways.
        Assert.Equal([Actor.Viewer], elsewhere.Actors.ToArray());
    }

    [Fact]
    public void A_component_grant_does_not_reach_upward_to_its_project()
    {
        var assignments = new[] { At(ProjectRole.LeadDev, component: ComponentA) };

        var atProject = Resolve(ScopeTarget.Project(ClientA, ProjectA), assignments);

        Assert.Equal([Actor.Viewer], atProject.Actors.ToArray());
    }

    // ------------------------------------------------------------------
    // Additive within a tier
    // ------------------------------------------------------------------

    [Fact]
    public void Roles_at_the_same_tier_are_unioned()
    {
        // "A three-person team should not be forced into an org chart it
        // doesn't have."
        var assignments = new[]
        {
            At(ProjectRole.LeadDev, project: ProjectA),
            At(ProjectRole.Architect, project: ProjectA),
        };

        var principal = Resolve(ScopeTarget.Project(ClientA, ProjectA), assignments);

        Assert.Contains(Actor.LeadDev, principal.Actors);
        Assert.Contains(Actor.Architect, principal.Actors);
        Assert.True(_evaluator.Allows(principal, Capability.ManageIngestKey)); // Lead Dev
        Assert.True(_evaluator.Allows(principal, Capability.CreateProject));   // Architect
    }

    // ------------------------------------------------------------------
    // Override across tiers — the consequential rule
    // ------------------------------------------------------------------

    [Fact]
    public void The_narrowest_tier_with_any_assignment_wins_entirely()
    {
        // The reconciliation: additive applies WITHIN a tier, override applies
        // ACROSS tiers. TFND-3 / F2.2 — "inherits from higher tier unless
        // explicitly overridden at the lower tier."
        var assignments = new[]
        {
            At(ProjectRole.InfoSecOfficer, client: ClientA),
            At(ProjectRole.LeadDev, component: ComponentA),
        };

        var atComponent = Resolve(ScopeTarget.Component(ClientA, ProjectA, ComponentA), assignments);

        Assert.Equal([Actor.LeadDev], atComponent.Actors.ToArray());
        Assert.DoesNotContain(Actor.InfoSecOfficer, atComponent.Actors);
    }

    [Fact]
    public void A_narrow_grant_can_remove_access_a_broader_one_gave()
    {
        // Deliberate and worth stating: making an organisation-wide InfoSec
        // Officer a Lead Dev on one component DEMOTES them there. It is the
        // only reading under which a narrow grant can express "here, this
        // person is only this" — which is the point of having tiers.
        var assignments = new[]
        {
            At(ProjectRole.InfoSecOfficer, client: ClientA),
            At(ProjectRole.LeadDev, component: ComponentA),
        };

        var atProject = Resolve(ScopeTarget.Project(ClientA, ProjectA), assignments);
        var atComponent = Resolve(ScopeTarget.Component(ClientA, ProjectA, ComponentA), assignments);

        // Still InfoSec on the project, where nothing overrides.
        Assert.True(_evaluator.Allows(atProject, Capability.AcceptRisk));
        // But not on the component they were narrowed on.
        Assert.False(_evaluator.Allows(atComponent, Capability.AcceptRisk));
    }

    [Fact]
    public void A_project_grant_silences_the_client_tier_but_not_a_component_tier()
    {
        var assignments = new[]
        {
            At(ProjectRole.InfoSecOfficer, client: ClientA),
            At(ProjectRole.Architect, project: ProjectA),
            At(ProjectRole.LeadDev, component: ComponentA),
        };

        Assert.Equal([Actor.InfoSecOfficer], Resolve(ScopeTarget.Client(ClientA), assignments).Actors.ToArray());
        Assert.Equal([Actor.Architect], Resolve(ScopeTarget.Project(ClientA, ProjectA), assignments).Actors.ToArray());
        Assert.Equal([Actor.LeadDev], Resolve(ScopeTarget.Component(ClientA, ProjectA, ComponentA), assignments).Actors.ToArray());
    }

    // ------------------------------------------------------------------
    // Degenerate input
    // ------------------------------------------------------------------

    [Fact]
    public void A_user_with_no_assignments_is_a_viewer_not_a_nobody()
    {
        var principal = Resolve(ScopeTarget.Project(ClientA, ProjectA));

        Assert.Equal([Actor.Viewer], principal.Actors.ToArray());
        Assert.True(_evaluator.Allows(principal, Capability.ViewEvidence));
    }

    [Fact]
    public void Another_users_assignments_are_ignored()
    {
        var someoneElse = new ProjectRoleAssignment
        {
            UserId = Guid.NewGuid(), Role = ProjectRole.InfoSecOfficer, ClientId = ClientA,
        };

        var principal = Resolve(ScopeTarget.Client(ClientA), someoneElse);

        Assert.Equal([Actor.Viewer], principal.Actors.ToArray());
    }

    [Fact]
    public void An_assignment_naming_no_tier_grants_nothing()
    {
        // Every assignment is scoped to at least a client, so this is a data
        // defect. Treating "no tier named" as "covers everything" would turn a
        // malformed row into instance-wide access.
        var malformed = At(ProjectRole.InfoSecOfficer);

        var principal = Resolve(ScopeTarget.Component(ClientA, ProjectA, ComponentA), malformed);

        Assert.Equal([Actor.Viewer], principal.Actors.ToArray());
    }

    [Fact]
    public void Admin_holds_at_instance_scope_where_no_assignment_can_reach()
    {
        // Every ProjectRoleAssignment names at least a client, so the System
        // panels can only be reached by the instance-level flag.
        var admin = _resolver.Resolve(User, "root", isAdmin: true, [], ScopeTarget.Instance);
        var ordinary = _resolver.Resolve(User, "user", isAdmin: false, [], ScopeTarget.Instance);

        Assert.Contains(Actor.Admin, admin.Actors);
        Assert.Equal([Actor.Viewer], ordinary.Actors.ToArray());
    }

    [Fact]
    public void Admin_survives_a_narrowing_grant()
    {
        // The instance flag is not a ProjectRoleAssignment, so tier override
        // does not apply to it. An admin who is also a Lead Dev on a component
        // is still an admin there.
        var assignments = new[] { At(ProjectRole.LeadDev, component: ComponentA) };

        var principal = _resolver.Resolve(User, "root", isAdmin: true, assignments,
            ScopeTarget.Component(ClientA, ProjectA, ComponentA));

        Assert.Contains(Actor.Admin, principal.Actors);
        Assert.Contains(Actor.LeadDev, principal.Actors);
    }
}
