using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Application.Tests;

// Every row of the hand-off's capability matrix (TFND-68).
//
// The matrix is the release contract for who may do what, and it is the thing
// the RBAC screen renders. A row that drifts from the code is worse than no
// matrix at all, so each one is asserted here rather than described in a
// comment.
public class CapabilityMatrixTests
{
    private readonly CapabilityEvaluator _evaluator = new();

    private Principal As(bool admin = false, params ProjectRole[] roles) =>
        Principal.For(Guid.NewGuid(), "test", admin, roles);

    private static Principal Viewer() => Principal.Viewer(Guid.NewGuid(), "viewer");

    private bool Can(Principal p, Capability c) => _evaluator.Evaluate(p, c).Allowed;

    // ------------------------------------------------------------------
    // The row that must never move
    // ------------------------------------------------------------------

    [Fact]
    public void Admin_cannot_accept_risk()
    {
        // "Note that Admin cannot accept risk — that is an Authorizing
        // Official decision, not a systems privilege."
        //
        // This looks like an oversight to anyone reading the matrix quickly,
        // and it is the single most likely cell to be "fixed" by accident.
        var admin = As(admin: true);

        var decision = _evaluator.Evaluate(admin, Capability.AcceptRisk);

        Assert.False(decision.Allowed);
        Assert.Contains("InfoSecOfficer", decision.Reason!, StringComparison.Ordinal);
    }

    [Fact]
    public void Only_infosec_can_accept_risk()
    {
        Assert.True(Can(As(roles: ProjectRole.InfoSecOfficer), Capability.AcceptRisk));

        Assert.False(Can(As(roles: ProjectRole.LeadDev), Capability.AcceptRisk));
        Assert.False(Can(As(roles: ProjectRole.Architect), Capability.AcceptRisk));
        Assert.False(Can(Viewer(), Capability.AcceptRisk));
        Assert.False(Can(As(admin: true), Capability.AcceptRisk));
    }

    // ------------------------------------------------------------------
    // Viewing and exporting
    // ------------------------------------------------------------------

    [Fact]
    public void Everyone_including_a_viewer_can_see_evidence()
    {
        Assert.True(Can(Viewer(), Capability.ViewEvidence));
        Assert.True(Can(As(admin: true), Capability.ViewEvidence));
        foreach (var role in Enum.GetValues<ProjectRole>())
            Assert.True(Can(As(roles: role), Capability.ViewEvidence));
    }

    [Fact]
    public void A_viewer_cannot_export_but_everyone_else_can()
    {
        // Export is the auditor's whole job, and the one thing separating a
        // Viewer from an Auditor.
        Assert.False(Can(Viewer(), Capability.ExportAttestation));

        Assert.True(Can(As(admin: true), Capability.ExportAttestation));
        Assert.True(Can(As(roles: ProjectRole.InfoSecOfficer), Capability.ExportAttestation));
        Assert.True(Can(As(roles: ProjectRole.LeadDev), Capability.ExportAttestation));
        Assert.True(Can(As(roles: ProjectRole.Architect), Capability.ExportAttestation));
    }

    // ------------------------------------------------------------------
    // Authoring
    // ------------------------------------------------------------------

    [Fact]
    public void An_auditor_authors_nothing()
    {
        var auditor = Principal.For(Guid.NewGuid(), "auditor", isAdmin: false, roles: []);
        // Until TFND-69 adds ProjectRole.Auditor, an auditor resolves as a
        // Viewer — which is already correctly denied authoring. This asserts
        // the property that matters rather than the enum value.
        Assert.False(Can(auditor, Capability.AuthorSuppression));
        Assert.False(Can(auditor, Capability.CreatePoamItem));
        Assert.False(Can(auditor, Capability.AuthorVex));
    }

    [Fact]
    public void Lead_dev_may_draft_a_vex_statement_but_not_publish_it()
    {
        // The matrix's ◐. Drafting and publishing are two capabilities because
        // the transition between them is a workflow (TFND-120), not a
        // permission check.
        var lead = As(roles: ProjectRole.LeadDev);

        var author = _evaluator.Evaluate(lead, Capability.AuthorVex);
        Assert.True(author.Allowed);
        Assert.True(author.Conditional);
        Assert.Contains("InfoSec", author.Reason!, StringComparison.Ordinal);

        Assert.False(Can(lead, Capability.PublishVex));
        Assert.True(Can(As(roles: ProjectRole.InfoSecOfficer), Capability.PublishVex));
    }

    // ------------------------------------------------------------------
    // Policy and gates
    // ------------------------------------------------------------------

    [Fact]
    public void Architect_may_duplicate_a_policy_but_not_edit_one_in_place()
    {
        var architect = As(roles: ProjectRole.Architect);

        Assert.True(Can(architect, Capability.DuplicatePolicy));

        var edit = _evaluator.Evaluate(architect, Capability.EditPolicyWeights);
        Assert.True(edit.Conditional);
        Assert.Contains("duplicate", edit.Reason!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Gates_are_the_release_contract_so_only_admin_and_infosec_edit_them()
    {
        Assert.True(Can(As(admin: true), Capability.EditGates));
        Assert.True(Can(As(roles: ProjectRole.InfoSecOfficer), Capability.EditGates));

        Assert.False(Can(As(roles: ProjectRole.LeadDev), Capability.EditGates));
        Assert.False(Can(As(roles: ProjectRole.Architect), Capability.EditGates));
        Assert.False(Can(Viewer(), Capability.EditGates));
    }

    // ------------------------------------------------------------------
    // Hierarchy and keys
    // ------------------------------------------------------------------

    [Fact]
    public void Projects_are_created_by_admin_and_architect_only()
    {
        Assert.True(Can(As(admin: true), Capability.CreateProject));
        Assert.True(Can(As(roles: ProjectRole.Architect), Capability.CreateProject));

        Assert.False(Can(As(roles: ProjectRole.InfoSecOfficer), Capability.CreateProject));
        Assert.False(Can(As(roles: ProjectRole.LeadDev), Capability.CreateProject));
    }

    [Fact]
    public void Components_are_created_by_admin_lead_dev_and_architect()
    {
        Assert.True(Can(As(admin: true), Capability.CreateComponent));
        Assert.True(Can(As(roles: ProjectRole.LeadDev), Capability.CreateComponent));
        Assert.True(Can(As(roles: ProjectRole.Architect), Capability.CreateComponent));

        Assert.False(Can(As(roles: ProjectRole.InfoSecOfficer), Capability.CreateComponent));
    }

    [Fact]
    public void Architect_cannot_recycle_the_ingest_key_because_it_breaks_ci()
    {
        Assert.True(Can(As(admin: true), Capability.ManageIngestKey));
        Assert.True(Can(As(roles: ProjectRole.InfoSecOfficer), Capability.ManageIngestKey));
        Assert.True(Can(As(roles: ProjectRole.LeadDev), Capability.ManageIngestKey));

        Assert.False(Can(As(roles: ProjectRole.Architect), Capability.ManageIngestKey));
    }

    [Fact]
    public void Infosec_may_assign_roles_only_at_or_below_their_own_scope()
    {
        Assert.True(Can(As(admin: true), Capability.AssignRoles));

        var infosec = _evaluator.Evaluate(As(roles: ProjectRole.InfoSecOfficer), Capability.AssignRoles);
        Assert.True(infosec.Conditional);
        Assert.Contains("scope", infosec.Reason!, StringComparison.OrdinalIgnoreCase);

        Assert.False(Can(As(roles: ProjectRole.LeadDev), Capability.AssignRoles));
        Assert.False(Can(As(roles: ProjectRole.Architect), Capability.AssignRoles));
    }

    // ------------------------------------------------------------------
    // Additive roles
    // ------------------------------------------------------------------

    [Fact]
    public void Roles_are_additive_and_effective_access_is_the_union()
    {
        // "A three-person team should not be forced into an org chart it
        // doesn't have." Lead Dev brings the ingest key, Architect brings
        // project creation; the union has both.
        var both = As(roles: [ProjectRole.LeadDev, ProjectRole.Architect]);

        Assert.True(Can(both, Capability.ManageIngestKey));   // from Lead Dev
        Assert.True(Can(both, Capability.CreateProject));     // from Architect

        // And still not the things neither role grants.
        Assert.False(Can(both, Capability.EditGates));
        Assert.False(Can(both, Capability.AcceptRisk));
    }

    [Fact]
    public void A_union_never_loses_a_capability_either_role_had_alone()
    {
        // Guards against an evaluator that returns on first match rather than
        // unioning — which would make access depend on role ORDER.
        foreach (var a in Enum.GetValues<ProjectRole>())
        foreach (var b in Enum.GetValues<ProjectRole>())
        {
            var alone = _evaluator.EffectiveCapabilities(As(roles: a));
            var union = _evaluator.EffectiveCapabilities(As(roles: [a, b]));

            Assert.True(alone.IsSubsetOf(union), $"{a} lost capabilities when combined with {b}");
        }
    }

    [Fact]
    public void A_user_with_no_role_resolves_to_viewer_rather_than_to_nothing()
    {
        // Viewer is the implicit default — the ABSENCE of a grant, not a
        // stored value. If this ever returned an empty actor set, every
        // capability check would deny and read access would break.
        var principal = Principal.For(Guid.NewGuid(), "nobody", isAdmin: false, roles: []);

        Assert.Contains(Actor.Viewer, principal.Actors);
        Assert.True(Can(principal, Capability.ViewEvidence));
    }

    // ------------------------------------------------------------------
    // Denials are readable
    // ------------------------------------------------------------------

    [Fact]
    public void A_denial_names_the_capability_and_who_could_grant_it()
    {
        // The UI disables a gated action and says why rather than hiding it,
        // and the audit log wants the same sentence. "Forbidden" serves
        // neither.
        var decision = _evaluator.Evaluate(Viewer(), Capability.EditGates);

        Assert.False(decision.Allowed);
        Assert.Contains("EditGates", decision.Reason!, StringComparison.Ordinal);
        Assert.Contains("Viewer", decision.Reason!, StringComparison.Ordinal);
    }

    [Fact]
    public void Every_capability_is_granted_to_someone()
    {
        // A capability no role can exercise is dead code that looks like a
        // feature.
        foreach (var capability in CapabilityMatrix.AllCapabilities)
        {
            var holders = CapabilityMatrix.AllActors
                .Count(a => CapabilityMatrix.Grants_(a, capability) || CapabilityMatrix.IsConditional(a, capability));

            Assert.True(holders > 0, $"{capability} is granted to no actor");
        }
    }
}
