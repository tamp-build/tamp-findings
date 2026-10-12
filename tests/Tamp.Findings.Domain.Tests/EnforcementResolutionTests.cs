using Tamp.Findings.Domain.Risk;
using Tamp.Findings.Domain.Values;
using Xunit;

namespace Tamp.Findings.Domain.Tests;

/// <summary>
/// Enforcement-mode resolution (ADR 0004, corrected by TFND-247).
///
/// One rule now: the authored mode is the strictest across the policy layers —
/// `PolicyLayerMerge` has already collapsed template → client → archetype →
/// project — and the instance mode is a floor when the deployment locks it.
///
/// This file used to assert most-specific-wins, with a case named
/// "project overrides client and instance" that passed while ADR 0007's table
/// said a lower layer could never weaken an upper one. Both could not be right;
/// the ADR was.
/// </summary>
public class EnforcementResolutionTests
{
    // ---- Unlocked: the authored mode stands -------------------------------

    [Fact]
    public void Unlocked_nothing_authored_uses_the_instance_mode()
    {
        Assert.Equal(EnforcementMode.Advisory,
            EnforcementResolution.Resolve(EnforcementMode.Advisory, instanceLocked: false, authoredMode: null));
        Assert.Equal(EnforcementMode.Enforcing,
            EnforcementResolution.Resolve(EnforcementMode.Enforcing, instanceLocked: false, authoredMode: null));
    }

    [Fact]
    public void Unlocked_an_authored_mode_beats_the_instance_default()
    {
        // Enforcing authored somewhere in the stack, on an advisory instance.
        Assert.Equal(EnforcementMode.Enforcing,
            EnforcementResolution.Resolve(
                EnforcementMode.Advisory, instanceLocked: false, authoredMode: EnforcementMode.Enforcing));
    }

    [Fact]
    public void Unlocked_an_authored_advisory_stands_when_nothing_stricter_exists()
    {
        // The merge is what decides this: if any layer had asked for Enforcing,
        // the authored mode reaching here would already BE Enforcing. Advisory
        // arriving means every layer that spoke said advisory, so honouring it
        // is not a weakening.
        Assert.Equal(EnforcementMode.Advisory,
            EnforcementResolution.Resolve(
                EnforcementMode.Advisory, instanceLocked: false, authoredMode: EnforcementMode.Advisory));
    }

    [Fact]
    public void A_lower_layer_can_no_longer_weaken_an_upper_one()
    {
        // TFND-247, and the whole point. Previously a client set to Enforcing
        // was undercut by a project set to Advisory, because this function
        // resolved project ?? client ?? instance. The merge now hands down the
        // strictest, so the Advisory never reaches here to win.
        var merged = PolicyLayerMerge.Resolve(
        [
            (new PolicyLayer { Mode = EnforcementMode.Enforcing }, "client"),
            (new PolicyLayer { Mode = EnforcementMode.Advisory }, "this project"),
        ]);

        Assert.Equal(EnforcementMode.Enforcing, merged.Mode!.Value);
        Assert.Equal("client", merged.Mode.Source);

        Assert.Equal(EnforcementMode.Enforcing,
            EnforcementResolution.Resolve(
                EnforcementMode.Advisory, instanceLocked: false, merged.Mode.Value));
    }

    // ---- Locked: the instance mode is a floor -----------------------------

    [Fact]
    public void Locked_an_authored_advisory_is_held_at_the_floor()
    {
        Assert.Equal(EnforcementMode.Enforcing,
            EnforcementResolution.Resolve(
                EnforcementMode.Enforcing, instanceLocked: true, authoredMode: EnforcementMode.Advisory));
    }

    [Fact]
    public void Locked_layers_may_exceed_the_floor()
    {
        Assert.Equal(EnforcementMode.Enforcing,
            EnforcementResolution.Resolve(
                EnforcementMode.Advisory, instanceLocked: true, authoredMode: EnforcementMode.Enforcing));
    }

    [Fact]
    public void Locked_with_nothing_authored_is_the_floor()
    {
        Assert.Equal(EnforcementMode.Enforcing,
            EnforcementResolution.Resolve(
                EnforcementMode.Enforcing, instanceLocked: true, authoredMode: null));
    }
}
