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

    // One client, one project, two components — the shape most of these tests
    // care about. The cross-tenant cases below name their own.
    private static readonly Guid Client1 = Guid.NewGuid();
    private static readonly Guid Project1 = Guid.NewGuid();
    private static readonly Guid Client2 = Guid.NewGuid();
    private static readonly Guid Project2 = Guid.NewGuid();

    private static readonly SuppressionTarget At1 = new(Client1, Project1, Component1);
    private static readonly SuppressionTarget At2 = new(Client1, Project1, Component2);

    /// <summary>A component under a DIFFERENT client entirely.</summary>
    private static readonly SuppressionTarget Elsewhere = new(Client2, Project2, Guid.NewGuid());

    private static Suppression Make(
        SuppressionScope scope,
        Guid? findingId = null,
        string? ruleId = null,
        Guid? componentId = null,
        string? filePath = null,
        DateTimeOffset? expiresAt = null,
        // Defaults to the one tenant, so the pre-TFND-132 tests read unchanged.
        // A null clientId is asked for explicitly, by the legacy-row tests.
        Guid? clientId = null,
        Guid? projectId = null,
        bool legacy = false) => new()
    {
        Scope = scope,
        FindingId = findingId,
        RuleId = ruleId,
        ComponentId = componentId,
        FilePath = filePath,
        ClientId = legacy ? null : clientId ?? Client1,
        ProjectId = legacy ? null : projectId,
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
        Assert.True(SuppressionMatcher.Covers(s, At1, "S2094", "src/Foo.cs", Finding1, Now));
        Assert.False(SuppressionMatcher.Covers(s, At1, "S2094", "src/Foo.cs", Finding2, Now));
    }

    [Fact]
    public void SingleFinding_doesnt_apply_on_insert_when_finding_id_is_null()
    {
        var s = Make(SuppressionScope.SingleFinding, findingId: Finding1);
        Assert.False(SuppressionMatcher.Covers(s, At1, "S2094", "src/Foo.cs", existingFindingId: null, Now));
    }

    // ----- RuleOnFile scope -----------------------------------------------

    [Fact]
    public void RuleOnFile_covers_same_rule_same_file()
    {
        var s = Make(SuppressionScope.RuleOnFile, ruleId: "S2094", filePath: "src/Foo.cs");
        Assert.True(SuppressionMatcher.Covers(s, At1, "S2094", "src/Foo.cs", null, Now));
    }

    [Fact]
    public void RuleOnFile_rejects_different_file()
    {
        var s = Make(SuppressionScope.RuleOnFile, ruleId: "S2094", filePath: "src/Foo.cs");
        Assert.False(SuppressionMatcher.Covers(s, At1, "S2094", "src/Bar.cs", null, Now));
    }

    [Fact]
    public void RuleOnFile_rejects_different_rule()
    {
        var s = Make(SuppressionScope.RuleOnFile, ruleId: "S2094", filePath: "src/Foo.cs");
        Assert.False(SuppressionMatcher.Covers(s, At1, "S1118", "src/Foo.cs", null, Now));
    }

    [Fact]
    public void RuleOnFile_normalizes_file_uri_against_plain_path()
    {
        // Roslyn emits file:/// URIs; suppressions are authored with plain
        // paths. The matcher must equate the two.
        var s = Make(SuppressionScope.RuleOnFile, ruleId: "S2094", filePath: "src/Tamp.Findings.Mcp/Placeholder.cs");
        Assert.True(SuppressionMatcher.Covers(
            s, At1, "S2094",
            "file:///C:/repos/tamp.findings/src/Tamp.Findings.Mcp/Placeholder.cs",
            null, Now));
    }

    [Fact]
    public void RuleOnFile_normalizes_backslash_path_separators()
    {
        var s = Make(SuppressionScope.RuleOnFile, ruleId: "S2094", filePath: "src\\Foo.cs");
        Assert.True(SuppressionMatcher.Covers(s, At1, "S2094", "src/Foo.cs", null, Now));
    }

    // ----- RuleOnComponent scope ------------------------------------------

    [Fact]
    public void RuleOnComponent_covers_same_rule_same_component()
    {
        var s = Make(SuppressionScope.RuleOnComponent, ruleId: "S2094", componentId: Component1);
        Assert.True(SuppressionMatcher.Covers(s, At1, "S2094", "src/Foo.cs", null, Now));
    }

    [Fact]
    public void RuleOnComponent_rejects_different_component()
    {
        var s = Make(SuppressionScope.RuleOnComponent, ruleId: "S2094", componentId: Component1);
        Assert.False(SuppressionMatcher.Covers(s, At2, "S2094", "src/Foo.cs", null, Now));
    }

    // ----- RuleEverywhere scope -------------------------------------------

    [Fact]
    public void RuleEverywhere_covers_same_rule_any_component_any_file()
    {
        var s = Make(SuppressionScope.RuleEverywhere, ruleId: "S2094");
        Assert.True(SuppressionMatcher.Covers(s, At1, "S2094", "src/Foo.cs", null, Now));
        Assert.True(SuppressionMatcher.Covers(s, At2, "S2094", "tests/Bar.cs", null, Now));
    }

    [Fact]
    public void RuleEverywhere_rejects_different_rule()
    {
        var s = Make(SuppressionScope.RuleEverywhere, ruleId: "S2094");
        Assert.False(SuppressionMatcher.Covers(s, At1, "S1118", "src/Foo.cs", null, Now));
    }

    // ----- Expiration -----------------------------------------------------

    [Fact]
    public void Expired_suppression_doesnt_cover_anything()
    {
        var s = Make(
            SuppressionScope.RuleEverywhere,
            ruleId: "S2094",
            expiresAt: Now.AddDays(-1));
        Assert.False(SuppressionMatcher.Covers(s, At1, "S2094", "src/Foo.cs", null, Now));
    }

    [Fact]
    public void Future_expiry_still_active()
    {
        var s = Make(
            SuppressionScope.RuleEverywhere,
            ruleId: "S2094",
            expiresAt: Now.AddDays(7));
        Assert.True(SuppressionMatcher.Covers(s, At1, "S2094", "src/Foo.cs", null, Now));
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
        Assert.False(SuppressionMatcher.Covers(s, At1, "S2094", "src/Foo.cs", null, Now));
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
        Assert.True(SuppressionMatcher.AnyCovers(pool, At1, "S2094", "src/Foo.cs", null, Now));
    }

    [Fact]
    public void AnyCovers_false_when_pool_empty()
    {
        Assert.False(SuppressionMatcher.AnyCovers([], At1, "S2094", "src/Foo.cs", null, Now));
    }

    [Fact]
    public void AnyCovers_false_when_only_expired_matches()
    {
        var pool = new[]
        {
            Make(SuppressionScope.RuleEverywhere, ruleId: "S2094", expiresAt: Now.AddDays(-1)),
        };
        Assert.False(SuppressionMatcher.AnyCovers(pool, At1, "S2094", "src/Foo.cs", null, Now));
    }

    // ----- Tenancy (TFND-132) ---------------------------------------------

    [Fact]
    public void A_rule_everywhere_suppression_does_not_reach_another_client()
    {
        // THE defect. RuleEverywhere matched on rule id alone, so one client's
        // decision silenced that rule for every other client on the instance —
        // invisibly, and in a way that changes what their attestation claims.
        var s = Make(SuppressionScope.RuleEverywhere, ruleId: "S2094");

        Assert.True(SuppressionMatcher.Covers(s, At1, "S2094", "src/Foo.cs", null, Now));
        Assert.False(SuppressionMatcher.Covers(s, Elsewhere, "S2094", "src/Foo.cs", null, Now));
    }

    [Fact]
    public void A_rule_on_file_suppression_does_not_reach_another_client()
    {
        // The same hole through the other unanchored scope, and the more
        // likely one to fire by accident: "src/Program.cs" exists in most
        // repositories on earth.
        var s = Make(SuppressionScope.RuleOnFile, ruleId: "S2094", filePath: "src/Program.cs");

        Assert.True(SuppressionMatcher.Covers(s, At1, "S2094", "src/Program.cs", null, Now));
        Assert.False(SuppressionMatcher.Covers(s, Elsewhere, "S2094", "src/Program.cs", null, Now));
    }

    [Fact]
    public void A_project_scoped_suppression_does_not_reach_a_sibling_project()
    {
        var s = Make(SuppressionScope.RuleEverywhere, ruleId: "S2094", projectId: Project1);
        var sibling = new SuppressionTarget(Client1, Guid.NewGuid(), Guid.NewGuid());

        Assert.True(SuppressionMatcher.Covers(s, At1, "S2094", "src/Foo.cs", null, Now));
        Assert.False(SuppressionMatcher.Covers(s, sibling, "S2094", "src/Foo.cs", null, Now));
    }

    [Fact]
    public void A_client_scoped_suppression_reaches_every_project_under_it()
    {
        // No project named means the author meant the whole client, which is a
        // grant they had to hold at the client tier to make.
        var s = Make(SuppressionScope.RuleEverywhere, ruleId: "S2094", projectId: null);
        var otherProject = new SuppressionTarget(Client1, Guid.NewGuid(), Guid.NewGuid());

        Assert.True(SuppressionMatcher.Covers(s, At1, "S2094", "src/Foo.cs", null, Now));
        Assert.True(SuppressionMatcher.Covers(s, otherProject, "S2094", "src/Foo.cs", null, Now));
    }

    [Fact]
    public void A_legacy_row_keeps_its_instance_wide_behaviour()
    {
        // Rows written before suppressions carried a tenant have no answer to
        // "whose was this". Narrowing them retroactively would silently
        // un-suppress findings people have already signed off — a compliance
        // claim changing under them with no action on their part, which is
        // worse than the defect. They stay global and the set only shrinks.
        var s = Make(SuppressionScope.RuleEverywhere, ruleId: "S2094", legacy: true);

        Assert.True(SuppressionMatcher.Covers(s, At1, "S2094", "src/Foo.cs", null, Now));
        Assert.True(SuppressionMatcher.Covers(s, Elsewhere, "S2094", "src/Foo.cs", null, Now));
    }

    [Fact]
    public void An_anchored_suppression_is_bounded_by_its_tenant_too()
    {
        // Belt and braces. A RuleOnComponent row already cannot match another
        // client's component — component ids are unique — but the tenant check
        // runs first for every scope, so a future scope cannot be added that
        // forgets it.
        var s = Make(SuppressionScope.RuleOnComponent, ruleId: "S2094", componentId: Component1);

        Assert.False(SuppressionMatcher.Covers(s, Elsewhere, "S2094", "src/Foo.cs", null, Now));
    }
}
