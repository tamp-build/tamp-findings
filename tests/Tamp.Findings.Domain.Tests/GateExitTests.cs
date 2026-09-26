using Tamp.Findings.Domain.Risk;
using Tamp.Findings.Domain.Values;
using Xunit;

namespace Tamp.Findings.Domain.Tests;

public class GateExitTests
{
    // ---- Advisory never fails the build -----------------------------------

    [Theory]
    [InlineData(GateOutcome.Pass)]
    [InlineData(GateOutcome.Fail)]
    [InlineData(GateOutcome.Unknown)]
    [InlineData(GateOutcome.Error)]
    [InlineData(GateOutcome.Unreachable)]
    public void Advisory_always_exits_zero(GateOutcome outcome)
    {
        Assert.Equal(GateExit.Ok, GateExit.CodeFor(outcome, EnforcementMode.Advisory));
    }

    // ---- Enforcing fails on anything that is not a definitive Pass --------

    [Theory]
    [InlineData(GateOutcome.Pass, 0)]
    [InlineData(GateOutcome.Fail, 10)]
    [InlineData(GateOutcome.Unknown, 11)]
    [InlineData(GateOutcome.Error, 12)]
    [InlineData(GateOutcome.Unreachable, 20)]
    public void Enforcing_maps_each_outcome_to_its_code(GateOutcome outcome, int expected)
    {
        Assert.Equal(expected, GateExit.CodeFor(outcome, EnforcementMode.Enforcing));
    }

    // ---- Outcome from verdicts --------------------------------------------

    [Fact]
    public void No_blocking_verdicts_is_pass()
    {
        Assert.Equal(GateOutcome.Pass,
            GateExit.OutcomeFrom([GateVerdict.Pass, GateVerdict.Pass]));
    }

    [Fact]
    public void Fail_outranks_error_and_unknown()
    {
        Assert.Equal(GateOutcome.Fail,
            GateExit.OutcomeFrom([GateVerdict.Unknown, GateVerdict.Fail, GateVerdict.Error, GateVerdict.Pass]));
    }

    [Fact]
    public void Error_outranks_unknown_when_no_fail()
    {
        Assert.Equal(GateOutcome.Error,
            GateExit.OutcomeFrom([GateVerdict.Unknown, GateVerdict.Error, GateVerdict.Pass]));
    }

    [Fact]
    public void Unknown_alone_blocks_as_unknown()
    {
        Assert.Equal(GateOutcome.Unknown,
            GateExit.OutcomeFrom([GateVerdict.Pass, GateVerdict.Unknown]));
    }

    [Fact]
    public void An_unscanned_build_never_reads_as_pass_under_enforcing()
    {
        // The core guarantee: a gate that could not be evaluated blocks.
        var outcome = GateExit.OutcomeFrom([GateVerdict.Unknown]);
        Assert.Equal(GateExit.Unknown, GateExit.CodeFor(outcome, EnforcementMode.Enforcing));
    }
}
