using Tamp.Findings.Domain.Risk;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Domain.Tests;

/// <summary>
/// Probe for TFND-247: is a loosening project write actually reachable?
///
/// Kept after the fix. The gate half established that PolicyLayerMerge already
/// prevents a project weakening what it inherits — which is why no validation
/// was added to GateService — and the mode half now records that enforcement
/// resolution agrees with the merge instead of contradicting it.
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
    public void And_enforcement_resolution_now_honours_it_too()
    {
        // FIXED by TFND-247, and this test is the record of the fix.
        //
        // It previously asserted the defect: EnforcementResolver ignored the
        // merged strictest-wins Mode and resolved
        // project ?? client ?? instance, so on an unlocked instance a project
        // override of Advisory beat a client's Enforcing — the opposite of the
        // merge above and of ADR 0007's table.
        //
        // The merged Mode is now the input to resolution, so the two agree.
        var merged = PolicyLayerMerge.Resolve(
        [
            Layer("client", l => l.Mode = EnforcementMode.Enforcing),
            Layer("this project", l => l.Mode = EnforcementMode.Advisory),
        ]);

        var effective = EnforcementResolution.Resolve(
            instanceMode: EnforcementMode.Advisory,
            instanceLocked: false,
            authoredMode: merged.Mode!.Value);

        Assert.Equal(EnforcementMode.Enforcing, effective);
    }

    [Fact]
    public void A_locked_instance_floor_still_outranks_everything()
    {
        // The lock is config-sourced and belongs to the platform team, so it
        // sits above the layer stack rather than inside it.
        var effective = EnforcementResolution.Resolve(
            instanceMode: EnforcementMode.Enforcing,
            instanceLocked: true,
            authoredMode: EnforcementMode.Advisory);

        Assert.Equal(EnforcementMode.Enforcing, effective);
    }
}
