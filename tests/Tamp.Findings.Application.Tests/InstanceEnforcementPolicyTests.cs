using Tamp.Findings.Application.Risk;
using Tamp.Findings.Domain.Values;
using Xunit;

namespace Tamp.Findings.Application.Tests;

public class InstanceEnforcementPolicyTests
{
    [Fact]
    public void Config_locked_overrides_the_database_values()
    {
        var policy = new InstanceEnforcementPolicy(configLocked: true, configMode: EnforcementMode.Enforcing);

        // DB says advisory/unlocked; config lock forces enforcing/locked.
        Assert.Equal((EnforcementMode.Enforcing, true), policy.Effective(EnforcementMode.Advisory, dbLocked: false));
    }

    [Fact]
    public void Unlocked_config_passes_the_database_values_through()
    {
        var policy = new InstanceEnforcementPolicy(configLocked: false, configMode: EnforcementMode.Enforcing);

        Assert.Equal((EnforcementMode.Advisory, false), policy.Effective(EnforcementMode.Advisory, dbLocked: false));
        Assert.Equal((EnforcementMode.Enforcing, true), policy.Effective(EnforcementMode.Enforcing, dbLocked: true));
    }
}
