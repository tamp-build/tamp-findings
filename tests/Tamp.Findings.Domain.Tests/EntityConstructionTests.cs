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
    public void ProjectRole_values_are_stable_because_they_are_persisted()
    {
        // The enum is stored as an int on ProjectRoleAssignment, so these
        // numbers are data. Renumbering one would silently re-grant every
        // existing assignment to a different role.
        //
        // This test used to assert the enum held exactly three roles. That
        // invariant was retired by TFND-69 when Auditor was added — and the
        // fact that it was ever true is what let SuppressionsEndpoints treat
        // "it parsed as a ProjectRole" as authorization. What matters is the
        // NUMBERING, not the count.
        Assert.Equal(1, (int)ProjectRole.InfoSecOfficer);
        Assert.Equal(2, (int)ProjectRole.LeadDev);
        Assert.Equal(3, (int)ProjectRole.Architect);
        Assert.Equal(4, (int)ProjectRole.Auditor);
    }

    [Fact]
    public void Every_project_role_has_a_distinct_persisted_value()
    {
        var values = Enum.GetValues<ProjectRole>().Select(r => (int)r).ToArray();

        Assert.Equal(values.Length, values.Distinct().Count());
        // Zero is the default for an int column; a role sitting on it would be
        // indistinguishable from an unset value.
        Assert.DoesNotContain(0, values);
    }
}
