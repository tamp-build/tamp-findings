using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Application.Tests;

// Separation of duties (TFND-72). Flagged, not blocked, by default.
public class SeparationOfDutiesTests
{
    [Fact]
    public void Lead_dev_plus_infosec_conflicts()
    {
        // Remediates and accepts risk on the same finding.
        var conflicts = SeparationOfDuties.Check([ProjectRole.LeadDev, ProjectRole.InfoSecOfficer]);

        Assert.Single(conflicts);
        Assert.Contains("accepts risk", conflicts[0], StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Architect_plus_infosec_conflicts()
    {
        // Authors the waiver and approves it.
        var conflicts = SeparationOfDuties.Check([ProjectRole.Architect, ProjectRole.InfoSecOfficer]);

        Assert.Single(conflicts);
        Assert.Contains("waiver", conflicts[0], StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Lead_dev_plus_architect_does_not_conflict()
    {
        // Both build; neither approves the other. Two roles being related is
        // not the same as one being the check on the other.
        Assert.Empty(SeparationOfDuties.Check([ProjectRole.LeadDev, ProjectRole.Architect]));
    }

    [Fact]
    public void Auditor_conflicts_with_nothing_because_it_authors_nothing()
    {
        foreach (var role in Enum.GetValues<ProjectRole>())
        {
            Assert.DoesNotContain(
                SeparationOfDuties.Check([ProjectRole.Auditor, role]),
                c => c.Contains("Auditor", StringComparison.Ordinal));
        }
    }

    [Fact]
    public void A_single_role_never_conflicts_with_itself()
    {
        foreach (var role in Enum.GetValues<ProjectRole>())
            Assert.Empty(SeparationOfDuties.Check([role]));
    }

    [Fact]
    public void Holding_all_three_named_roles_reports_both_conflicts()
    {
        var conflicts = SeparationOfDuties.Check(
            [ProjectRole.LeadDev, ProjectRole.Architect, ProjectRole.InfoSecOfficer]);

        Assert.Equal(2, conflicts.Count);
    }

    [Fact]
    public void Only_newly_introduced_conflicts_are_reported_on_a_grant()
    {
        // The grant dialog shows the advisory BEFORE committing. Repeating a
        // conflict the person already had would be noise on every subsequent
        // grant, and noise is how an advisory gets ignored.
        var alreadyConflicted = new[] { ProjectRole.LeadDev, ProjectRole.InfoSecOfficer };

        var introduced = SeparationOfDuties.WouldIntroduce(alreadyConflicted, [ProjectRole.Auditor]);

        Assert.Empty(introduced);
    }

    [Fact]
    public void A_grant_that_creates_a_conflict_reports_exactly_that_conflict()
    {
        var introduced = SeparationOfDuties.WouldIntroduce(
            [ProjectRole.LeadDev], [ProjectRole.InfoSecOfficer]);

        Assert.Single(introduced);
        Assert.Contains("Lead Dev", introduced[0], StringComparison.Ordinal);
    }

    [Fact]
    public void Adding_a_third_role_reports_only_the_second_conflict()
    {
        // Already Lead Dev + InfoSec (one conflict). Adding Architect creates
        // the Architect + InfoSec conflict and nothing else.
        var introduced = SeparationOfDuties.WouldIntroduce(
            [ProjectRole.LeadDev, ProjectRole.InfoSecOfficer], [ProjectRole.Architect]);

        Assert.Single(introduced);
        Assert.Contains("Architect", introduced[0], StringComparison.Ordinal);
    }

    [Fact]
    public void Enforcement_is_off_by_default()
    {
        // A three-person team genuinely needs one person to hold two of these.
        // Refusing by default would make the product unusable for exactly the
        // organisation it is aimed at, so the switch defaults off and the
        // conflict is merely recorded.
        var settings = new InstanceSettings();

        Assert.False(settings.EnforceSeparationOfDuties);
    }

    [Fact]
    public void A_conflict_is_recorded_on_the_assignment_rather_than_recomputed()
    {
        // The assessor needs to see what the granter was TOLD and accepted at
        // the moment they accepted it — not what today's rules would say about
        // a combination granted three years ago.
        var assignment = new ProjectRoleAssignment
        {
            UserId = Guid.NewGuid(),
            Role = ProjectRole.InfoSecOfficer,
            SodConflict = SeparationOfDuties.Check([ProjectRole.LeadDev, ProjectRole.InfoSecOfficer])[0],
        };

        Assert.NotNull(assignment.SodConflict);
        Assert.Contains("accepts risk", assignment.SodConflict, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void No_conflict_leaves_the_flag_null_rather_than_empty()
    {
        // Null and "" would render identically but filter differently. Null is
        // the only honest value for "no conflict".
        var introduced = SeparationOfDuties.WouldIntroduce([ProjectRole.LeadDev], [ProjectRole.Architect]);

        Assert.Empty(introduced);
    }
}
