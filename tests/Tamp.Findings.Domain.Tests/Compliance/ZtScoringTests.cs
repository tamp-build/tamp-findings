using Tamp.Findings.Domain.Compliance;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Domain.Tests;

// The Zero Trust derivation (TFND-188 / ADR 0010). Conservative-by-construction:
// undetermined floors at 1, inherited caps at the provider, N/A leaves the denominator.
// These pin every disposition, the precedence, and the equal-weight scoring.
public class ZtScoringTests
{
    private static ZtFunctionDef Fn(string id, bool cc = false) =>
        new() { Id = id, Name = id, CrossCutting = cc, Stages = [] };

    // Model: P1 has F1,F2,CC(cross-cutting); P2 has G1.
    private static MaturityModelCatalog Model() => new()
    {
        Name = "T", Version = "1", Source = "t",
        Pillars =
        [
            new() { Id = "P1", Name = "P1", Functions = [Fn("F1"), Fn("F2"), Fn("CC", cc: true)] },
            new() { Id = "P2", Name = "P2", Functions = [Fn("G1")] },
        ],
    };

    private static DateTimeOffset Now => DateTimeOffset.Parse("2026-01-01T00:00:00Z");

    private static ZtFunctionResult F(ZtCoverage c, string fn) => c.Functions.Single(x => x.Function == fn);

    [Fact]
    public void Nothing_known_floors_every_function_at_1_never_zero()
    {
        var c = ZtDispositionResolver.Resolve(Model(), [], [], [], Now);
        Assert.All(c.Functions, f => Assert.Equal(1, f.Stage));
        Assert.All(c.Functions, f => Assert.Equal(ZtDisposition.Undetermined, f.Disposition));
        Assert.Equal(4, c.Undetermined);
        // Equal-weight mean of 1s = 1; no zeros anywhere.
        Assert.Equal(1.0, c.SystemScore);
    }

    [Fact]
    public void Na_pick_leaves_the_denominator_and_is_never_a_1()
    {
        var picks = new[] { new ZtPickInput("P2", "G1", ZtPickKind.NotApplicable) };
        var c = ZtDispositionResolver.Resolve(Model(), [], [], picks, Now);

        var g1 = F(c, "G1");
        Assert.Equal(ZtDisposition.NotApplicable, g1.Disposition);
        Assert.False(g1.InDenominator);
        // P2 was ONLY G1 → the whole pillar drops out of the system score (not a 1).
        Assert.Null(c.Pillars.Single(p => p.Pillar == "P2").Score);
        Assert.Equal(1.0, c.SystemScore); // only P1 (all undetermined 1s) counts
    }

    [Fact]
    public void Owned_pass_is_verified_at_its_stage_fail_is_contradicted_at_the_floor()
    {
        var owned = new[]
        {
            new ZtOwnedEvidence("P1", "F1", 3, ZtOwnedVerdict.Pass),
            new ZtOwnedEvidence("P1", "F2", 4, ZtOwnedVerdict.Fail),
        };
        var c = ZtDispositionResolver.Resolve(Model(), owned, [], [], Now);

        Assert.Equal(ZtDisposition.OwnedVerified, F(c, "F1").Disposition);
        Assert.Equal(3, F(c, "F1").Stage);
        // Claimed stage 4 but the code contradicts it → no credit, floors at 1.
        Assert.Equal(ZtDisposition.OwnedContradicted, F(c, "F2").Disposition);
        Assert.Equal(1, F(c, "F2").Stage);
        Assert.Equal(1, c.Contradicted);
    }

    [Fact]
    public void Owned_unknown_is_committed_at_the_adr_stage()
    {
        var owned = new[] { new ZtOwnedEvidence("P1", "F1", 2, ZtOwnedVerdict.Unknown) };
        var c = ZtDispositionResolver.Resolve(Model(), owned, [], [], Now);
        Assert.Equal(ZtDisposition.OwnedCommitted, F(c, "F1").Disposition);
        Assert.Equal(2, F(c, "F1").Stage);
    }

    [Fact]
    public void Inherited_attested_needs_a_statement_and_an_unexpired_date()
    {
        var future = Now.AddDays(30);
        var edges = new[] { new ZtEdgeInput("P1", "F1", ProviderStage: 3, HasStatement: true, ExpiresAt: future) };
        var c = ZtDispositionResolver.Resolve(Model(), [], edges, [], Now);
        Assert.Equal(ZtDisposition.InheritedAttested, F(c, "F1").Disposition);
        Assert.Equal(3, F(c, "F1").Stage); // capped at the provider
    }

    [Fact]
    public void Inherited_is_committed_when_unattested_or_stale()
    {
        var edges = new[]
        {
            new ZtEdgeInput("P1", "F1", 3, HasStatement: false, ExpiresAt: null),      // bare pick
            new ZtEdgeInput("P1", "F2", 4, HasStatement: true, ExpiresAt: Now.AddDays(-1)), // stale
        };
        var c = ZtDispositionResolver.Resolve(Model(), [], edges, [], Now);
        Assert.Equal(ZtDisposition.InheritedCommitted, F(c, "F1").Disposition);
        Assert.Equal(ZtDisposition.InheritedCommitted, F(c, "F2").Disposition);
        Assert.Equal(4, F(c, "F2").Stage); // still scores the provider stage, just flagged
    }

    [Fact]
    public void Edge_wins_over_owned_but_na_pick_wins_over_everything()
    {
        var owned = new[] { new ZtOwnedEvidence("P1", "F1", 2, ZtOwnedVerdict.Pass) };
        var edges = new[] { new ZtEdgeInput("P1", "F1", 4, HasStatement: true, ExpiresAt: Now.AddDays(30)) };
        var picks = new[] { new ZtPickInput("P1", "F1", ZtPickKind.NotApplicable) };

        // owned + edge → edge wins (the enterprise source the repo can't see).
        var edgeWins = ZtDispositionResolver.Resolve(Model(), owned, edges, [], Now);
        Assert.Equal(ZtDisposition.InheritedAttested, F(edgeWins, "F1").Disposition);

        // + N/A pick → N/A wins over both.
        var naWins = ZtDispositionResolver.Resolve(Model(), owned, edges, picks, Now);
        Assert.Equal(ZtDisposition.NotApplicable, F(naWins, "F1").Disposition);
    }

    [Fact]
    public void Pillar_is_the_equal_weight_mean_and_cross_cutting_folds_in_at_the_same_weight()
    {
        // P1: F1=3 (verified), F2=1 (undetermined), CC=1 (undetermined) → mean (3+1+1)/3 = 1.667
        var owned = new[] { new ZtOwnedEvidence("P1", "F1", 3, ZtOwnedVerdict.Pass) };
        var c = ZtDispositionResolver.Resolve(Model(), owned, [], [], Now);

        var p1 = c.Pillars.Single(p => p.Pillar == "P1");
        Assert.Equal((3.0 + 1 + 1) / 3, p1.Score!.Value, 3);
        // System score = mean of P1 (1.667) and P2 (1) = 1.333
        Assert.Equal(((3.0 + 1 + 1) / 3 + 1.0) / 2, c.SystemScore!.Value, 3);
    }
}
