using Tamp.Findings.Domain.Compliance;
using Tamp.Findings.Domain.Risk;

namespace Tamp.Findings.Domain.Tests;

// The control-disposition model (TFND-185 / ADR 0009). Every in-scope control
// resolves to exactly one disposition; the no-unmapped meta-gate blocks on the
// gap. These pin the four dispositions, the capability intersection, and the
// meta-gate's three verdicts.
public class ControlDispositionTests
{
    private static Control Ctrl(string id, string family = "CM") =>
        new() { Id = id, Title = $"{id} title", Family = family, Baselines = BaselineLevel.High };

    private static EffectiveAssertion Gated(params string[] gates) =>
        new(ControlDispositionKind.Gated, gates, null, null, "FedRAMP High");

    private static Dictionary<string, EffectiveAssertion> Map(params (string Id, EffectiveAssertion A)[] items)
    {
        var d = new Dictionary<string, EffectiveAssertion>(StringComparer.OrdinalIgnoreCase);
        foreach (var (id, a) in items) d[id] = a;
        return d;
    }

    [Fact]
    public void Control_with_no_assertion_is_unmapped()
    {
        var cov = ControlDispositionResolver.Resolve([Ctrl("AC-2")], Map(), capability: null);

        Assert.Equal(1, cov.InScope);
        Assert.Equal(1, cov.Unmapped);
        Assert.False(cov.Complete);
        Assert.Equal(ControlDisposition.Unmapped, cov.Controls[0].Disposition);
        Assert.Null(cov.Controls[0].Source);
    }

    [Fact]
    public void Gated_assertion_with_an_applicable_gate_is_gated()
    {
        var cov = ControlDispositionResolver.Resolve(
            [Ctrl("RA-5")],
            Map(("RA-5", Gated(GateKeys.CriticalCves))),
            capability: ComponentCapability.Source | ComponentCapability.Deps);

        Assert.Equal(1, cov.Gated);
        Assert.Equal(ControlDisposition.Gated, cov.Controls[0].Disposition);
        Assert.Contains("Critical CVEs", cov.Controls[0].Detail);
        Assert.Equal("FedRAMP High", cov.Controls[0].Source);
    }

    [Fact]
    public void Gated_by_only_inapplicable_gates_resolves_to_not_applicable_via_capability()
    {
        // SC-7 gated solely by criticalDast (needs Web); a code-package has no Web.
        var codePackage = ComponentProfiles.Capabilities(ComponentProfile.CodePackage);

        var cov = ControlDispositionResolver.Resolve(
            [Ctrl("SC-7")],
            Map(("SC-7", Gated(GateKeys.CriticalDast))),
            capability: codePackage);

        Assert.Equal(1, cov.NotApplicable);
        Assert.Equal(0, cov.Gated);
        Assert.Equal(ControlDisposition.NotApplicable, cov.Controls[0].Disposition);
        Assert.Contains("cannot produce", cov.Controls[0].Detail);
    }

    [Fact]
    public void Gated_by_a_mix_stays_gated_when_at_least_one_gate_applies()
    {
        // Gated by criticalDast (Web, N/A) AND criticalCves (always applies).
        var codePackage = ComponentProfiles.Capabilities(ComponentProfile.CodePackage);

        var cov = ControlDispositionResolver.Resolve(
            [Ctrl("SI-2")],
            Map(("SI-2", Gated(GateKeys.CriticalDast, GateKeys.CriticalCves))),
            capability: codePackage);

        Assert.Equal(ControlDisposition.Gated, cov.Controls[0].Disposition);
    }

    [Fact]
    public void Null_capability_never_downgrades_a_gated_control()
    {
        // The profile view (build-independent) passes null: a DAST-gated control
        // stays Gated rather than resolving to N/A.
        var cov = ControlDispositionResolver.Resolve(
            [Ctrl("SC-7")],
            Map(("SC-7", Gated(GateKeys.CriticalDast))),
            capability: null);

        Assert.Equal(ControlDisposition.Gated, cov.Controls[0].Disposition);
    }

    [Fact]
    public void Inherited_and_asserted_na_carry_their_justification()
    {
        var map = Map(
            ("PE-3", new EffectiveAssertion(ControlDispositionKind.Inherited, [], "physical", "the IaaS", "tpl")),
            ("AC-18", new EffectiveAssertion(ControlDispositionKind.NotApplicable, [], "no wireless", null, "tpl")));

        var cov = ControlDispositionResolver.Resolve([Ctrl("PE-3", "PE"), Ctrl("AC-18", "AC")], map, capability: null);

        var pe = cov.Controls.Single(c => c.ControlId == "PE-3");
        Assert.Equal(ControlDisposition.Inherited, pe.Disposition);
        Assert.Contains("the IaaS", pe.Detail);

        var ac = cov.Controls.Single(c => c.ControlId == "AC-18");
        Assert.Equal(ControlDisposition.NotApplicable, ac.Disposition);
        Assert.Contains("no wireless", ac.Detail);

        Assert.Equal(1, cov.Inherited);
        Assert.Equal(1, cov.NotApplicable);
    }

    [Fact]
    public void Coverage_counts_every_disposition()
    {
        var map = Map(
            ("RA-5", Gated(GateKeys.CriticalCves)),
            ("PE-3", new EffectiveAssertion(ControlDispositionKind.Inherited, [], "physical", "IaaS", "tpl")),
            ("SC-7", Gated(GateKeys.CriticalDast)));
        var codePackage = ComponentProfiles.Capabilities(ComponentProfile.CodePackage);

        var cov = ControlDispositionResolver.Resolve(
            [Ctrl("RA-5"), Ctrl("PE-3"), Ctrl("SC-7"), Ctrl("AC-2")], map, codePackage);

        Assert.Equal(4, cov.InScope);
        Assert.Equal(1, cov.Gated);          // RA-5
        Assert.Equal(1, cov.Inherited);      // PE-3
        Assert.Equal(1, cov.NotApplicable);  // SC-7 (DAST, code-package)
        Assert.Equal(1, cov.Unmapped);       // AC-2
    }

    // ── PolicyLayerMerge: assertion merge (strictest-wins, gate union) ──

    [Fact]
    public void Assertion_merge_takes_the_strictest_kind_and_unions_gates()
    {
        var template = new PolicyLayer
        {
            Assertions =
            {
                new ControlAssertion { Kind = ControlDispositionKind.NotApplicable, ControlIds = ["RA-5"], Justification = "n/a here" },
            },
        };
        var project = new PolicyLayer
        {
            Assertions =
            {
                new ControlAssertion { Kind = ControlDispositionKind.Gated, ControlIds = ["RA-5"], Gates = [GateKeys.CriticalCves] },
            },
        };

        var merged = PolicyLayerMerge.Resolve([(template, "FedRAMP"), (project, "this project")]);

        // Gated (0) is stricter than NotApplicable (2); the project's gated claim wins.
        Assert.Equal(ControlDispositionKind.Gated, merged.Assertions["RA-5"].Kind);
        Assert.Equal("this project", merged.Assertions["RA-5"].Source);
    }

    [Fact]
    public void Assertion_merge_unions_gates_across_layers_for_the_same_control()
    {
        var a = new PolicyLayer { Assertions = { new ControlAssertion { Kind = ControlDispositionKind.Gated, ControlIds = ["SI-2"], Gates = [GateKeys.KevExposure] } } };
        var b = new PolicyLayer { Assertions = { new ControlAssertion { Kind = ControlDispositionKind.Gated, ControlIds = ["SI-2"], Gates = [GateKeys.PoamPastDue] } } };

        var merged = PolicyLayerMerge.Resolve([(a, "tpl"), (b, "client")]);

        Assert.Equal(2, merged.Assertions["SI-2"].Gates.Count);
        Assert.Contains(GateKeys.KevExposure, merged.Assertions["SI-2"].Gates);
        Assert.Contains(GateKeys.PoamPastDue, merged.Assertions["SI-2"].Gates);
    }

    // ── The no-unmapped meta-gate ──

    private static ProjectGatesConfig NoUnmappedOn() =>
        new() { Gates = { [GateKeys.NoUnmapped] = new GateConfig { Enabled = true } } };

    private static RiskInputs EmptyInputs() => new(
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        false, 0, 0, 0, 0, false, 0, 0, 0, 0, 0,
        false, false, false, false, false);

    [Fact]
    public void Meta_gate_passes_when_every_control_is_dispositioned()
    {
        var coverage = new ControlCoverage(10, 6, 2, 2, 0, []);
        var eval = GateEvaluator.Evaluate(NoUnmappedOn(), EmptyInputs(), 0, null, null, capability: null, coverage: coverage);

        var g = eval.Results.Single(r => r.Key == GateKeys.NoUnmapped);
        Assert.Equal(GateVerdict.Pass, g.Verdict);
        Assert.False(g.Blocks);
    }

    [Fact]
    public void Meta_gate_fails_when_a_control_is_unmapped()
    {
        var coverage = new ControlCoverage(10, 4, 1, 0, 5, []);
        var eval = GateEvaluator.Evaluate(NoUnmappedOn(), EmptyInputs(), 0, null, null, capability: null, coverage: coverage);

        var g = eval.Results.Single(r => r.Key == GateKeys.NoUnmapped);
        Assert.Equal(GateVerdict.Fail, g.Verdict);
        Assert.True(g.Blocks);
        Assert.Contains("5 of 10", g.Observed);
    }

    [Fact]
    public void Meta_gate_is_unknown_when_coverage_is_absent()
    {
        // No framework/catalog → coverage null → cannot answer, blocks like any Unknown.
        var eval = GateEvaluator.Evaluate(NoUnmappedOn(), EmptyInputs(), 0, null, null, capability: null, coverage: null);

        var g = eval.Results.Single(r => r.Key == GateKeys.NoUnmapped);
        Assert.Equal(GateVerdict.Unknown, g.Verdict);
        Assert.True(g.Blocks);
    }

    [Fact]
    public void Meta_gate_disabled_does_not_block_and_ignores_coverage()
    {
        var coverage = new ControlCoverage(10, 0, 0, 0, 10, []);
        var eval = GateEvaluator.Evaluate(new ProjectGatesConfig(), EmptyInputs(), 0, null, null, capability: null, coverage: coverage);

        var g = eval.Results.Single(r => r.Key == GateKeys.NoUnmapped);
        Assert.False(g.Enabled);
        Assert.False(g.Blocks);
    }
}
