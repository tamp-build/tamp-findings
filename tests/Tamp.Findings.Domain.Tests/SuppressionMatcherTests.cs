using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Suppressions;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Domain.Tests;

public class SuppressionMatcherTests
{
    private static readonly DateTimeOffset Now = new(2026, 5, 19, 12, 0, 0, TimeSpan.Zero);
    private static readonly Guid TestUser = Guid.NewGuid();
    private static readonly Guid Component1 = Guid.NewGuid();
    private static readonly Guid Component2 = Guid.NewGuid();
    private static readonly Guid Finding1 = Guid.NewGuid();
    private static readonly Guid Finding2 = Guid.NewGuid();

    private static Suppression Make(
        SuppressionScope scope,
        Guid? findingId = null,
        string? ruleId = null,
        Guid? componentId = null,
        string? filePath = null,
        DateTimeOffset? expiresAt = null) => new()
    {
        Scope = scope,
        FindingId = findingId,
        RuleId = ruleId,
        ComponentId = componentId,
        FilePath = filePath,
        CreatedByUserId = TestUser,
        CreatedByRole = ProjectRole.InfoSecOfficer,
        Reason = "test",
        ExpiresAt = expiresAt,
    };

    // ----- SingleFinding scope --------------------------------------------

    [Fact]
    public void SingleFinding_covers_only_its_target_id()
    {
        var s = Make(SuppressionScope.SingleFinding, findingId: Finding1);
        Assert.True(SuppressionMatcher.Covers(s, Component1, "S2094", "src/Foo.cs", Finding1, Now));
        Assert.False(SuppressionMatcher.Covers(s, Component1, "S2094", "src/Foo.cs", Finding2, Now));
    }

    [Fact]
    public void SingleFinding_doesnt_apply_on_insert_when_finding_id_is_null()
    {
        var s = Make(SuppressionScope.SingleFinding, findingId: Finding1);
        Assert.False(SuppressionMatcher.Covers(s, Component1, "S2094", "src/Foo.cs", existingFindingId: null, Now));
    }

    // ----- RuleOnFile scope -----------------------------------------------

    [Fact]
    public void RuleOnFile_covers_same_rule_same_file()
    {
        var s = Make(SuppressionScope.RuleOnFile, ruleId: "S2094", filePath: "src/Foo.cs");
        Assert.True(SuppressionMatcher.Covers(s, Component1, "S2094", "src/Foo.cs", null, Now));
    }

    [Fact]
    public void RuleOnFile_rejects_different_file()
    {
        var s = Make(SuppressionScope.RuleOnFile, ruleId: "S2094", filePath: "src/Foo.cs");
        Assert.False(SuppressionMatcher.Covers(s, Component1, "S2094", "src/Bar.cs", null, Now));
    }

    [Fact]
    public void RuleOnFile_rejects_different_rule()
    {
        var s = Make(SuppressionScope.RuleOnFile, ruleId: "S2094", filePath: "src/Foo.cs");
        Assert.False(SuppressionMatcher.Covers(s, Component1, "S1118", "src/Foo.cs", null, Now));
    }

    [Fact]
    public void RuleOnFile_normalizes_file_uri_against_plain_path()
    {
        // Roslyn emits file:/// URIs; suppressions are authored with plain
        // paths. The matcher must equate the two.
        var s = Make(SuppressionScope.RuleOnFile, ruleId: "S2094", filePath: "src/Tamp.Findings.Mcp/Placeholder.cs");
        Assert.True(SuppressionMatcher.Covers(
            s, Component1, "S2094",
            "file:///C:/repos/tamp.findings/src/Tamp.Findings.Mcp/Placeholder.cs",
            null, Now));
    }

    [Fact]
    public void RuleOnFile_normalizes_backslash_path_separators()
    {
        var s = Make(SuppressionScope.RuleOnFile, ruleId: "S2094", filePath: "src\\Foo.cs");
        Assert.True(SuppressionMatcher.Covers(s, Component1, "S2094", "src/Foo.cs", null, Now));
    }

    // ----- RuleOnComponent scope ------------------------------------------

    [Fact]
    public void RuleOnComponent_covers_same_rule_same_component()
    {
        var s = Make(SuppressionScope.RuleOnComponent, ruleId: "S2094", componentId: Component1);
        Assert.True(SuppressionMatcher.Covers(s, Component1, "S2094", "src/Foo.cs", null, Now));
    }

    [Fact]
    public void RuleOnComponent_rejects_different_component()
    {
        var s = Make(SuppressionScope.RuleOnComponent, ruleId: "S2094", componentId: Component1);
        Assert.False(SuppressionMatcher.Covers(s, Component2, "S2094", "src/Foo.cs", null, Now));
    }

    // ----- RuleEverywhere scope -------------------------------------------

    [Fact]
    public void RuleEverywhere_covers_same_rule_any_component_any_file()
    {
        var s = Make(SuppressionScope.RuleEverywhere, ruleId: "S2094");
        Assert.True(SuppressionMatcher.Covers(s, Component1, "S2094", "src/Foo.cs", null, Now));
        Assert.True(SuppressionMatcher.Covers(s, Component2, "S2094", "tests/Bar.cs", null, Now));
    }

    [Fact]
    public void RuleEverywhere_rejects_different_rule()
    {
        var s = Make(SuppressionScope.RuleEverywhere, ruleId: "S2094");
        Assert.False(SuppressionMatcher.Covers(s, Component1, "S1118", "src/Foo.cs", null, Now));
    }

    // ----- Expiration -----------------------------------------------------

    [Fact]
    public void Expired_suppression_doesnt_cover_anything()
    {
        var s = Make(
            SuppressionScope.RuleEverywhere,
            ruleId: "S2094",
            expiresAt: Now.AddDays(-1));
        Assert.False(SuppressionMatcher.Covers(s, Component1, "S2094", "src/Foo.cs", null, Now));
    }

    [Fact]
    public void Future_expiry_still_active()
    {
        var s = Make(
            SuppressionScope.RuleEverywhere,
            ruleId: "S2094",
            expiresAt: Now.AddDays(7));
        Assert.True(SuppressionMatcher.Covers(s, Component1, "S2094", "src/Foo.cs", null, Now));
    }

    [Fact]
    public void Expiry_exactly_at_now_counts_as_expired()
    {
        // Defensive: a suppression set to expire "right now" should not still
        // be in force — `<=` is the boundary for expiration.
        var s = Make(
            SuppressionScope.RuleEverywhere,
            ruleId: "S2094",
            expiresAt: Now);
        Assert.False(SuppressionMatcher.Covers(s, Component1, "S2094", "src/Foo.cs", null, Now));
    }

    // ----- AnyCovers -------------------------------------------------------

    [Fact]
    public void AnyCovers_returns_true_when_any_suppression_in_the_pool_matches()
    {
        var pool = new[]
        {
            Make(SuppressionScope.RuleEverywhere, ruleId: "OTHER"),
            Make(SuppressionScope.RuleOnFile, ruleId: "S2094", filePath: "src/Foo.cs"),
        };
        Assert.True(SuppressionMatcher.AnyCovers(pool, Component1, "S2094", "src/Foo.cs", null, Now));
    }

    [Fact]
    public void AnyCovers_false_when_pool_empty()
    {
        Assert.False(SuppressionMatcher.AnyCovers([], Component1, "S2094", "src/Foo.cs", null, Now));
    }

    [Fact]
    public void AnyCovers_false_when_only_expired_matches()
    {
        var pool = new[]
        {
            Make(SuppressionScope.RuleEverywhere, ruleId: "S2094", expiresAt: Now.AddDays(-1)),
        };
        Assert.False(SuppressionMatcher.AnyCovers(pool, Component1, "S2094", "src/Foo.cs", null, Now));
    }
}
