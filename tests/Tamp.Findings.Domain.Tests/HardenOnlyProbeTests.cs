using Tamp.Findings.Domain.Risk;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Domain.Tests;

/// <summary>
/// Probe for TFND-247: is a loosening project write actually reachable?
///
/// ADR 0007 claims the write side enforces harden-only and GateService does not
/// validate it, which looked like a hole. Before adding a validation, these
/// check whether the merge already makes a loosening write ineffective — a
/// validation that rejects something the merge already neutralises is a
/// validation nobody needs, and it would reject honest storage the product
/// deliberately allows.
/// </summary>
public class HardenOnlyProbeTests
{
    private static (PolicyLayer, string) Layer(string source, Action<PolicyLayer> set)
    {
        var l = PolicyLayer.Empty();
        set(l);
        return (l, source);
    }

    [Fact]
    public void A_project_cannot_disable_a_gate_its_client_enabled()
    {
        var client = Layer("client", l => l.Gates["criticalCve"] = new GateConfig { Enabled = true, Threshold = 0 });
        var project = Layer("this project", l => l.Gates["criticalCve"] = new GateConfig { Enabled = false, Threshold = 0 });

        var merged = PolicyLayerMerge.Resolve([client, project]);

        // Enabled is OR across layers, so the project's false cannot win.
        Assert.True(merged.Gates["criticalCve"].Enabled);
    }

    [Fact]
    public void A_project_cannot_raise_a_threshold_above_its_clients()
    {
        var client = Layer("client", l => l.Gates["highCve"] = new GateConfig { Enabled = true, Threshold = 3 });
        var project = Layer("this project", l => l.Gates["highCve"] = new GateConfig { Enabled = true, Threshold = 50 });

        var merged = PolicyLayerMerge.Resolve([client, project]);

        // Threshold is the min of provided values — lower is stricter.
        Assert.Equal(3, merged.Gates["highCve"].Threshold);
        Assert.Equal("client", merged.Gates["highCve"].Source);
    }

    [Fact]
    public void A_project_may_set_whatever_it_likes_on_a_gate_nothing_above_it_sets()
    {
        // Not a loosening: there is nothing inherited to be looser than. A
        // validation that rejected this would stop a project owning its own
        // gate, which is the normal case on an instance with no template.
        var project = Layer("this project", l => l.Gates["coverageFloor"] = new GateConfig { Enabled = false });

        var merged = PolicyLayerMerge.Resolve([project]);

        Assert.False(merged.Gates["coverageFloor"].Enabled);
    }

    [Fact]
    public void Merged_mode_is_strictest_wins_as_ADR_0007_says()
    {
        var client = Layer("client", l => l.Mode = EnforcementMode.Enforcing);
        var project = Layer("this project", l => l.Mode = EnforcementMode.Advisory);

        var merged = PolicyLayerMerge.Resolve([client, project]);

        Assert.Equal(EnforcementMode.Enforcing, merged.Mode!.Value);
        Assert.Equal("client", merged.Mode.Source);
    }

    [Fact]
    public void But_enforcement_resolution_lets_a_project_weaken_its_clients_mode()
    {
        // The path actually used for a verdict. EnforcementResolver does NOT read
        // the merged layer's strictest-wins Mode — it resolves
        // project ?? client ?? instance, most-specific-wins, and only applies a
        // floor when the INSTANCE is locked.
        //
        // So with an unlocked instance, a project override of Advisory beats a
        // client's Enforcing: the opposite of what the merge above computes and
        // of what ADR 0007's table states.
        var effective = EnforcementResolution.Resolve(
            instanceMode: EnforcementMode.Advisory,
            instanceLocked: false,
            clientMode: EnforcementMode.Enforcing,
            projectMode: EnforcementMode.Advisory);

        Assert.Equal(EnforcementMode.Advisory, effective);
    }

    [Fact]
    public void A_locked_instance_floor_does_stop_the_weakening()
    {
        var effective = EnforcementResolution.Resolve(
            instanceMode: EnforcementMode.Enforcing,
            instanceLocked: true,
            clientMode: EnforcementMode.Enforcing,
            projectMode: EnforcementMode.Advisory);

        Assert.Equal(EnforcementMode.Enforcing, effective);
    }
}
