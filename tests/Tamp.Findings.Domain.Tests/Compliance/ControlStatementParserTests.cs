using Tamp.Findings.Domain.Compliance;

namespace Tamp.Findings.Domain.Tests;

// The statement parser feeds the control-statement panel (v3 §6). Getting a
// nested parameter wrong would split one organization-defined decision into
// several chips, so the depth-counting cases are the ones that matter.
public class ControlStatementParserTests
{
    [Fact]
    public void Plain_prose_is_a_single_text_segment()
    {
        var segs = ControlStatementParser.Parse("Protect the authenticity of communications sessions.");
        var seg = Assert.Single(segs);
        Assert.False(seg.IsParameter);
    }

    [Fact]
    public void A_single_assignment_splits_text_param_text()
    {
        // SC-13 a.
        var segs = ControlStatementParser.Parse("a. Determine the [Assignment: organization-defined cryptographic uses]; and");

        Assert.Equal(3, segs.Count);
        Assert.False(segs[0].IsParameter);
        Assert.True(segs[1].IsParameter);
        Assert.Equal(ParameterKind.Assignment, segs[1].Kind);
        Assert.Equal("[Assignment: organization-defined cryptographic uses]", segs[1].Text);
        Assert.False(segs[2].IsParameter);
    }

    [Fact]
    public void A_nested_selection_is_one_chip_not_several()
    {
        // CM-3 g. — a Selection whose options themselves contain Assignments.
        const string line = "g. Coordinate and provide oversight for configuration change control activities through "
            + "[Assignment: organization-defined configuration change control element] that convenes "
            + "[Selection (one or more): [Assignment: organization-defined frequency]; when [Assignment: organization-defined configuration change conditions]].";

        var segs = ControlStatementParser.Parse(line);
        var parameters = segs.Where(s => s.IsParameter).ToArray();

        // Exactly two top-level parameters: the assignment, then the whole
        // nested selection as ONE chip.
        Assert.Equal(2, parameters.Length);
        Assert.Equal(ParameterKind.Assignment, parameters[0].Kind);
        Assert.Equal(ParameterKind.Selection, parameters[1].Kind);
        // The selection chip carries its nested assignments whole.
        Assert.Contains("when [Assignment: organization-defined configuration change conditions]", parameters[1].Text);
        Assert.EndsWith("]", parameters[1].Text);
    }

    [Fact]
    public void Multiple_parameters_on_one_line_each_become_a_chip()
    {
        // CM-6 c.
        const string line = "c. Identify, document, and approve any deviations from established configuration settings for "
            + "[Assignment: organization-defined system components] based on "
            + "[Assignment: organization-defined operational requirements]; and";

        var parameters = ControlStatementParser.Parse(line).Where(s => s.IsParameter).ToArray();
        Assert.Equal(2, parameters.Length);
        Assert.All(parameters, p => Assert.Equal(ParameterKind.Assignment, p.Kind));
    }

    [Fact]
    public void Selection_kind_is_detected()
    {
        // SC-7 b.
        var parameters = ControlStatementParser.Parse(
            "b. Implement subnetworks that are [Selection: physically; logically] separated; and")
            .Where(s => s.IsParameter).ToArray();

        var p = Assert.Single(parameters);
        Assert.Equal(ParameterKind.Selection, p.Kind);
    }

    [Fact]
    public void Baseline_flags_parse_to_the_right_levels()
    {
        Assert.Equal(BaselineLevel.Low | BaselineLevel.Moderate | BaselineLevel.High, ControlStatementParser.ParseBaselines("LMH"));
        Assert.Equal(BaselineLevel.Moderate | BaselineLevel.High, ControlStatementParser.ParseBaselines("MH"));
        Assert.Equal(BaselineLevel.High, ControlStatementParser.ParseBaselines("H"));
        Assert.Equal(BaselineLevel.None, ControlStatementParser.ParseBaselines(""));
    }

    [Fact]
    public void A_control_reports_membership_and_its_parameters()
    {
        var control = new Control
        {
            Id = "SI-6", Title = "Security and Privacy Function Verification",
            Family = "System and Information Integrity", Baselines = BaselineLevel.High,
            StatementLines =
            {
                "a. Verify the correct operation of [Assignment: organization-defined security and privacy functions];",
                "d. [Selection (one or more): Shut the system down; Restart the system; [Assignment: organization-defined alternative action(s)]] when anomalies are discovered.",
            },
        };

        Assert.True(control.InBaseline(BaselineLevel.High));
        Assert.False(control.InBaseline(BaselineLevel.Low));
        // One assignment on line a, one selection (nested) on line d = 2.
        Assert.Equal(2, control.Parameters.Count);
        Assert.Equal(2, ControlStatementParser.CountParameters(control.StatementLines));
    }
}
