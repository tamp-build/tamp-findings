using Tamp.Findings.Domain.Risk;
using Tamp.Findings.Domain.Values;
using Xunit;

namespace Tamp.Findings.Domain.Tests;

public class EnforcementResolutionTests
{
    // ---- Unlocked: most-specific wins -------------------------------------

    [Fact]
    public void Unlocked_nothing_set_uses_the_instance_mode()
    {
        Assert.Equal(EnforcementMode.Advisory,
            EnforcementResolution.Resolve(EnforcementMode.Advisory, instanceLocked: false, clientMode: null, projectMode: null));
        Assert.Equal(EnforcementMode.Enforcing,
            EnforcementResolution.Resolve(EnforcementMode.Enforcing, instanceLocked: false, clientMode: null, projectMode: null));
    }

    [Fact]
    public void Unlocked_project_overrides_client_and_instance()
    {
        var mode = EnforcementResolution.Resolve(
            EnforcementMode.Enforcing, instanceLocked: false,
            clientMode: EnforcementMode.Enforcing, projectMode: EnforcementMode.Advisory);
        Assert.Equal(EnforcementMode.Advisory, mode);
    }

    [Fact]
    public void Unlocked_client_used_when_project_unset()
    {
        var mode = EnforcementResolution.Resolve(
            EnforcementMode.Advisory, instanceLocked: false,
            clientMode: EnforcementMode.Enforcing, projectMode: null);
        Assert.Equal(EnforcementMode.Enforcing, mode);
    }

    // ---- Locked: instance mode is a floor, projects may only go stricter ---

    [Fact]
    public void Locked_project_cannot_weaken_below_the_floor()
    {
        // Floor is enforcing; a project asking for advisory is held at the floor.
        var mode = EnforcementResolution.Resolve(
            EnforcementMode.Enforcing, instanceLocked: true,
            clientMode: EnforcementMode.Advisory, projectMode: EnforcementMode.Advisory);
        Assert.Equal(EnforcementMode.Enforcing, mode);
    }

    [Fact]
    public void Locked_project_may_exceed_the_floor()
    {
        // Floor is advisory; a project asking for enforcing is honored.
        var mode = EnforcementResolution.Resolve(
            EnforcementMode.Advisory, instanceLocked: true,
            clientMode: null, projectMode: EnforcementMode.Enforcing);
        Assert.Equal(EnforcementMode.Enforcing, mode);
    }

    [Fact]
    public void Locked_with_nothing_set_is_the_floor()
    {
        var mode = EnforcementResolution.Resolve(
            EnforcementMode.Enforcing, instanceLocked: true, clientMode: null, projectMode: null);
        Assert.Equal(EnforcementMode.Enforcing, mode);
    }
}
