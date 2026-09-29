using Tamp.Findings.Domain.Compliance;
using Tamp.Findings.Domain.Risk;

namespace Tamp.Findings.Domain.Tests;

// The review-gated adrConformance gate (TFND-191 / ADR 0006). The block/pass mapping
// from the (already review-filtered) conformance summary. The review/verify/disposition
// filtering itself is exercised in the integration tests (needs the rule store + DB).
public class ConformanceGateTests
{
    private static ProjectGatesConfig On() =>
        new() { Gates = { [GateKeys.AdrConformance] = new GateConfig { Enabled = true } } };

    private static RiskInputs Empty() => new(
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        false, 0, 0, 0, 0, false, 0, 0, 0, 0, 0,
        false, false, false, false, false);

    private static GateResult Eval(ProjectGatesConfig cfg, ConformanceSummary? s) =>
        GateEvaluator.Evaluate(cfg, Empty(), 0, null, null, capability: null, coverage: null, conformance: s)
            .Results.Single(r => r.Key == GateKeys.AdrConformance);

    [Fact]
    public void Disabled_is_not_enabled_and_does_not_block()
    {
        var g = Eval(new ProjectGatesConfig(), new ConformanceSummary(5, 3, 1));
        Assert.False(g.Enabled);
        Assert.False(g.Blocks);
    }

    [Fact]
    public void No_evidence_is_unknown_and_blocks()
    {
        Assert.Equal(GateVerdict.Unknown, Eval(On(), null).Verdict);
        var g = Eval(On(), new ConformanceSummary(0, 0, 0));
        Assert.Equal(GateVerdict.Unknown, g.Verdict);
        Assert.True(g.Blocks);
    }

    [Fact]
    public void A_reviewed_undispositioned_fail_blocks_as_fail()
    {
        var g = Eval(On(), new ConformanceSummary(Evaluated: 90, BlockingFails: 7, BlockingUnknowns: 52));
        Assert.Equal(GateVerdict.Fail, g.Verdict);
        Assert.True(g.Blocks);
        Assert.Contains("7 reviewed", g.Observed);
    }

    [Fact]
    public void Reviewed_unknowns_with_no_fail_block_as_unknown()
    {
        var g = Eval(On(), new ConformanceSummary(Evaluated: 90, BlockingFails: 0, BlockingUnknowns: 4));
        Assert.Equal(GateVerdict.Unknown, g.Verdict);
        Assert.True(g.Blocks);
    }

    [Fact]
    public void Evidence_with_nothing_blocking_passes()
    {
        // e.g. all pass, or all fails were Draft-ruled / dispositioned / unconfirmed —
        // filtered out upstream, so the summary shows 0 blocking.
        var g = Eval(On(), new ConformanceSummary(Evaluated: 90, BlockingFails: 0, BlockingUnknowns: 0));
        Assert.Equal(GateVerdict.Pass, g.Verdict);
        Assert.False(g.Blocks);
        Assert.Contains("90", g.Observed);
    }
}
