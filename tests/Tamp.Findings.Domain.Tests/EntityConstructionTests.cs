using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Domain.Tests;

public class EntityConstructionTests
{
    [Fact]
    public void Finding_defaults_to_Open_status_with_FirstSeen_and_LastSeen_set()
    {
        var f = new Finding
        {
            Hash = "deadbeef",
            RuleId = "rule.x",
            Title = "demo",
        };

        Assert.Equal(FindingStatus.Open, f.Status);
        Assert.NotEqual(default, f.FirstSeen);
        Assert.NotEqual(default, f.LastSeen);
    }

    [Fact]
    public void Severity_ordinals_are_stable_for_persistence()
    {
        Assert.Equal(0, (int)Severity.Info);
        Assert.Equal(1, (int)Severity.Low);
        Assert.Equal(2, (int)Severity.Medium);
        Assert.Equal(3, (int)Severity.High);
        Assert.Equal(4, (int)Severity.Critical);
    }

    [Fact]
    public void ProjectRole_only_contains_the_three_authoring_roles()
    {
        var names = Enum.GetNames<ProjectRole>();
        Assert.Equal(3, names.Length);
        Assert.Contains("InfoSecOfficer", names);
        Assert.Contains("LeadDev", names);
        Assert.Contains("Architect", names);
    }
}
