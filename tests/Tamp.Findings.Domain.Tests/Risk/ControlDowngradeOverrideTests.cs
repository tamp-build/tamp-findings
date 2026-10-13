using Tamp.Findings.Domain.Compliance;
using Tamp.Findings.Domain.Risk;

namespace Tamp.Findings.Domain.Tests.Risk;

/// <summary>
/// The one exception to harden-only: a reviewed project downgrade (ADR 0015 §5, TFND-219).
///
/// <see cref="HardenOnlyProbeTests"/> records that the merge neutralises a loosening
/// write, which is why no write-side validation was added. This change punches a hole in
/// that, so these tests are about how NARROW the hole is: only an assertion carrying
/// <see cref="ControlAssertion.Overrides"/> bends the rule, and that flag is only ever
/// written by ControlDowngradeEffect on an approved request.
/// </summary>
public class ControlDowngradeOverrideTests
{
    private static (PolicyLayer, string) Layer(string source, params ControlAssertion[] assertions)
    {
        var l = PolicyLayer.Empty();
        l.Assertions.AddRange(assertions);
        return (l, source);
    }

    private static ControlAssertion Gated(string controlId, params string[] gates) => new()
    {
        Kind = ControlDispositionKind.Gated, ControlIds = [controlId], Gates = [.. gates],
    };

    private static ControlAssertion NotApplicable(string controlId, bool overrides = false) => new()
    {
        Kind = ControlDispositionKind.NotApplicable,
        ControlIds = [controlId],
        Justification = "no cryptography of its own",
        Overrides = overrides,
    };

    [Fact]
    public void Without_the_flag_a_project_downgrade_still_loses()
    {
        // The guarantee this feature must not break. An ordinary project assertion
        // cannot weaken a stricter default, so an unscanned control does not pass.
        var merged = PolicyLayerMerge.Resolve([
            Layer("FedRAMP High", Gated("SC-13", "secrets")),
            Layer("this project", NotApplicable("SC-13")),
        ]);

        var a = merged.Assertions["SC-13"];
        Assert.Equal(ControlDispositionKind.Gated, a.Kind);
        Assert.Equal("FedRAMP High", a.Source);
        Assert.False(a.Overridden);
    }

    [Fact]
    public void With_the_flag_the_project_wins_and_says_it_was_an_override()
    {
        var merged = PolicyLayerMerge.Resolve([
            Layer("FedRAMP High", Gated("SC-13", "secrets")),
            Layer("this project", NotApplicable("SC-13", overrides: true)),
        ]);

        var a = merged.Assertions["SC-13"];
        Assert.Equal(ControlDispositionKind.NotApplicable, a.Kind);
        Assert.Equal("this project", a.Source);
        Assert.Equal("no cryptography of its own", a.Justification);

        // Reported, not silent. A downgrade that looked like any other claim would be
        // the one row on a coverage matrix an assessor cannot find.
        Assert.True(a.Overridden);
    }

    [Fact]
    public void A_stricter_later_layer_does_not_quietly_undo_an_override()
    {
        // Layer order is template, archetype, project in production, so this ordering is
        // artificial — but the rule has to hold whatever the order, because the
        // alternative is a reviewed decision being reversed by a generic default that
        // nobody looked at.
        var merged = PolicyLayerMerge.Resolve([
            Layer("this project", NotApplicable("SC-13", overrides: true)),
            Layer("Library archetype", Gated("SC-13", "secrets")),
        ]);

        var a = merged.Assertions["SC-13"];
        Assert.Equal(ControlDispositionKind.NotApplicable, a.Kind);
        Assert.True(a.Overridden);
    }

    [Fact]
    public void An_override_still_unions_the_gate_lists()
    {
        // The disposition changes; what gates cover the control does not become a lie.
        // A later reviewer reading the row needs to see which gates were producing
        // evidence for it before somebody decided it did not apply.
        var merged = PolicyLayerMerge.Resolve([
            Layer("FedRAMP High", Gated("SC-13", "secrets")),
            Layer("Library archetype", Gated("SC-13", "sbomSigned")),
            Layer("this project", NotApplicable("SC-13", overrides: true)),
        ]);

        Assert.Equal(["secrets", "sbomSigned"], merged.Assertions["SC-13"].Gates);
    }

    [Fact]
    public void An_override_on_a_control_nothing_else_asserts_is_just_a_fill()
    {
        // Reaching this needs an approval all the same, because the authoring endpoint
        // refuses to guess: it checks the inherited stack and only calls something a
        // downgrade when a lower layer really is stricter.
        var merged = PolicyLayerMerge.Resolve([
            Layer("this project", NotApplicable("AU-11", overrides: true)),
        ]);

        var a = merged.Assertions["AU-11"];
        Assert.Equal(ControlDispositionKind.NotApplicable, a.Kind);
        Assert.True(a.Overridden);
    }

    [Fact]
    public void An_upgrade_needs_no_override_and_is_not_marked_as_one()
    {
        // The tamp-http SC-13 case from ADR 0015 §4: a project claiming it OWNS a
        // control already wins on strictness, so it must not be dressed up as an
        // exception — nothing was weakened and nobody needed to approve it.
        var merged = PolicyLayerMerge.Resolve([
            Layer("FedRAMP High", new ControlAssertion
            {
                Kind = ControlDispositionKind.Inherited,
                ControlIds = ["SC-13"],
                InheritedFrom = "the platform",
            }),
            Layer("this project", Gated("SC-13", "secrets")),
        ]);

        var a = merged.Assertions["SC-13"];
        Assert.Equal(ControlDispositionKind.Gated, a.Kind);
        Assert.False(a.Overridden);
    }

    [Fact]
    public void The_coverage_matrix_carries_the_override_through_to_the_reader()
    {
        var merged = PolicyLayerMerge.Resolve([
            Layer("FedRAMP High", Gated("SC-13", "secrets"), Gated("AU-11", "sbomSigned")),
            Layer("this project", NotApplicable("SC-13", overrides: true)),
        ]);

        var coverage = ControlDispositionResolver.Resolve(
            [
                new Control { Id = "SC-13", Title = "Cryptographic Protection", Family = "System and Communications Protection" },
                new Control { Id = "AU-11", Title = "Audit Record Retention", Family = "Audit and Accountability" },
            ],
            merged.Assertions,
            capability: null);

        var downgraded = coverage.Controls.Single(c => c.ControlId == "SC-13");
        Assert.Equal(ControlDisposition.NotApplicable, downgraded.Disposition);
        Assert.True(downgraded.Overridden);

        // And the ordinary row beside it is not marked, so the flag means something.
        Assert.False(coverage.Controls.Single(c => c.ControlId == "AU-11").Overridden);
    }
}
