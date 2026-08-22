using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Application.Tests;

// The Auditor role and the explicit Viewer (TFND-69).
public class AuditorRoleTests
{
    private readonly CapabilityEvaluator _evaluator = new();

    private Principal As(params ProjectRole[] roles) =>
        Principal.For(Guid.NewGuid(), "test", isAdmin: false, roles);

    private bool Can(Principal p, Capability c) => _evaluator.Evaluate(p, c).Allowed;

    [Fact]
    public void An_auditor_can_read_and_export()
    {
        var auditor = As(ProjectRole.Auditor);

        Assert.True(Can(auditor, Capability.ViewEvidence));
        // Export is the distinguishing capability — "the auditor's whole job",
        // and the only thing separating an Auditor from a Viewer.
        Assert.True(Can(auditor, Capability.ExportAttestation));
    }

    [Fact]
    public void An_auditor_authors_nothing_at_all()
    {
        var auditor = As(ProjectRole.Auditor);

        // The point of the role: an assessor gets everything they need to
        // review, and no way to change what they are reviewing.
        foreach (var capability in CapabilityMatrix.AllCapabilities)
        {
            if (capability is Capability.ViewEvidence or Capability.ExportAttestation) continue;

            Assert.False(Can(auditor, capability),
                $"Auditor unexpectedly granted {capability} — an auditor authors nothing");
        }
    }

    [Fact]
    public void Auditor_and_viewer_differ_only_by_export()
    {
        var auditor = _evaluator.EffectiveCapabilities(As(ProjectRole.Auditor));
        var viewer = _evaluator.EffectiveCapabilities(Principal.Viewer(Guid.NewGuid(), "v"));

        var difference = auditor.Except(viewer).ToArray();

        Assert.Equal([Capability.ExportAttestation], difference);
    }

    [Fact]
    public void Every_project_role_maps_to_an_actor()
    {
        // Principal.For throws on an unmapped role rather than falling through
        // to Viewer, so a role added later fails loudly instead of quietly
        // becoming read-only. This asserts the mapping is complete today.
        foreach (var role in Enum.GetValues<ProjectRole>())
        {
            var principal = As(role);

            Assert.Single(principal.Actors);
            Assert.DoesNotContain(Actor.Viewer, principal.Actors);
        }
    }

    [Fact]
    public void Auditor_is_additive_like_every_other_role()
    {
        // Someone can be both an Auditor and a Lead Dev — a small team is
        // exactly the case the additive model exists for. The union must not
        // let Auditor's read-only nature subtract anything.
        var both = As(ProjectRole.Auditor, ProjectRole.LeadDev);

        Assert.True(Can(both, Capability.AuthorSuppression));  // from Lead Dev
        Assert.True(Can(both, Capability.ExportAttestation));  // from either
        Assert.False(Can(both, Capability.EditGates));         // from neither
    }

    [Fact]
    public void Adding_a_role_to_the_enum_does_not_widen_what_it_may_do()
    {
        // The regression this ticket had to avoid. Before Auditor existed, the
        // enum happened to contain only roles that could author suppressions,
        // so parsing a role doubled as authorization by accident.
        //
        // Any code that infers permission from "it parsed as a ProjectRole"
        // is now wrong, and this asserts why: at least one role in the enum
        // cannot author.
        var nonAuthoring = Enum.GetValues<ProjectRole>()
            .Where(r => !Can(As(r), Capability.AuthorSuppression))
            .ToArray();

        Assert.NotEmpty(nonAuthoring);
        Assert.Contains(ProjectRole.Auditor, nonAuthoring);
    }
}
