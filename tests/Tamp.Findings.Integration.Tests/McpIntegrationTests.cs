using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Mcp;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Integration.Tests;

// The agent surface (TFND-12 / F11).
//
// The scoping rule is the whole feature, and it is the kind of rule that is
// obviously right in a review and wrong in a join. These tests seed TWO sibling
// components under two projects under two clients and then check, at every
// tier, that a token sees its subtree and nothing beside it.
[Collection(DatabaseCollection.Name)]
public class McpIntegrationTests
{
    private readonly DatabaseFixture _fx;

    public McpIntegrationTests(DatabaseFixture fx) => _fx = fx;

    // ---- Minting ------------------------------------------------------------

    [SkippableFact]
    public async Task A_minted_token_returns_its_plaintext_exactly_once_and_stores_only_a_hash()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var tokens = scope.ServiceProvider.GetRequiredService<McpTokenService>();
        var db = _fx.Db(scope);

        var minted = await tokens.MintAsync(
            world.Admin, world.ProjectScope, "claude · remediation", null, 30);

        Assert.True(minted.Success);
        Assert.StartsWith("mcp_", minted.Value!.Plaintext, StringComparison.Ordinal);

        var stored = await db.McpTokens.SingleAsync(t => t.Id == minted.Value.Id);
        Assert.DoesNotContain(minted.Value.Plaintext, stored.TokenHash, StringComparison.Ordinal);
    }

    [SkippableFact]
    public async Task The_prefix_is_distinct_from_the_ingest_prefixes()
    {
        Skip.IfNot(_fx.Available);

        // A token pasted into the wrong place should fail at the door rather
        // than be tried against a lookup it can never match.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var tokens = scope.ServiceProvider.GetRequiredService<McpTokenService>();

        var minted = await tokens.MintAsync(world.Admin, world.ProjectScope, "claude", null, 30);

        Assert.DoesNotContain("cli_", minted.Value!.Plaintext, StringComparison.Ordinal);
        Assert.DoesNotContain("prj_", minted.Value.Plaintext, StringComparison.Ordinal);
    }

    [SkippableFact]
    public async Task A_token_expires_by_default()
    {
        Skip.IfNot(_fx.Available);

        // Agents are given credentials and then forgotten about. A read token
        // that outlives the agent it was minted for is a standing grant to
        // whatever now holds it.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var tokens = scope.ServiceProvider.GetRequiredService<McpTokenService>();
        var db = _fx.Db(scope);

        var minted = await tokens.MintAsync(world.Admin, world.ProjectScope, "claude", null, null);
        var stored = await db.McpTokens.SingleAsync(t => t.Id == minted.Value!.Id);

        Assert.NotNull(stored.ExpiresAt);
        Assert.True(stored.ExpiresAt > DateTimeOffset.UtcNow.AddDays(80));
    }

    [SkippableFact]
    public async Task An_unlabelled_token_is_refused()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var tokens = scope.ServiceProvider.GetRequiredService<McpTokenService>();

        var result = await tokens.MintAsync(world.Admin, world.ProjectScope, "  ", null, 30);

        Assert.False(result.Success);
        Assert.False(result.WasDenied);
    }

    [SkippableFact]
    public async Task An_unscoped_token_is_refused()
    {
        Skip.IfNot(_fx.Available);

        // An instance-wide read token would be a standing grant over every
        // tenant on a multi-client deployment.
        using var scope = _fx.Scope();
        var tokens = scope.ServiceProvider.GetRequiredService<McpTokenService>();
        var world = await SeedAsync();

        var result = await tokens.MintAsync(world.Admin, ScopeTarget.Instance, "everything", null, 30);

        Assert.False(result.Success);
    }

    [SkippableFact]
    public async Task A_lead_dev_cannot_mint_an_agent_token()
    {
        Skip.IfNot(_fx.Available);

        // Minting a read token for an agent is granting access, so it needs the
        // capability that grants access.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var tokens = scope.ServiceProvider.GetRequiredService<McpTokenService>();

        var result = await tokens.MintAsync(world.LeadDev, world.ProjectScope, "claude", null, 30);

        Assert.True(result.WasDenied);
    }

    [SkippableFact]
    public async Task Nobody_can_mint_an_agent_that_holds_more_than_they_do()
    {
        Skip.IfNot(_fx.Available);

        // Otherwise "give the bot InfoSecOfficer" is how anyone reaches
        // AcceptRisk — a decision the matrix withholds even from Admin.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var tokens = scope.ServiceProvider.GetRequiredService<McpTokenService>();

        var result = await tokens.MintAsync(
            world.Admin, world.ProjectScope, "claude", ProjectRole.InfoSecOfficer, 30);

        Assert.False(result.Success);
        Assert.Contains("InfoSecOfficer", result.Error!, StringComparison.Ordinal);
    }

    // ---- Resolving ----------------------------------------------------------

    [SkippableFact]
    public async Task A_revoked_token_stops_resolving()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var tokens = scope.ServiceProvider.GetRequiredService<McpTokenService>();

        var minted = await tokens.MintAsync(world.Admin, world.ProjectScope, "claude", null, 30);
        Assert.NotNull(await tokens.ResolveAsync(minted.Value!.Plaintext, DateTimeOffset.UtcNow));

        await tokens.RevokeAsync(world.Admin, world.ProjectScope, minted.Value.Id);

        Assert.Null(await tokens.ResolveAsync(minted.Value.Plaintext, DateTimeOffset.UtcNow));
    }

    [SkippableFact]
    public async Task An_expired_token_stops_resolving_without_anyone_revoking_it()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var tokens = scope.ServiceProvider.GetRequiredService<McpTokenService>();

        var minted = await tokens.MintAsync(world.Admin, world.ProjectScope, "claude", null, 1);

        // Two days on, nobody has touched it and it is already inert.
        Assert.Null(await tokens.ResolveAsync(
            minted.Value!.Plaintext, DateTimeOffset.UtcNow.AddDays(2)));
    }

    [SkippableFact]
    public async Task A_token_from_another_instance_resolves_to_nothing()
    {
        Skip.IfNot(_fx.Available);

        using var scope = _fx.Scope();
        var tokens = scope.ServiceProvider.GetRequiredService<McpTokenService>();

        Assert.Null(await tokens.ResolveAsync("mcp_not-a-real-token", DateTimeOffset.UtcNow));
        Assert.Null(await tokens.ResolveAsync("", DateTimeOffset.UtcNow));
        Assert.Null(await tokens.ResolveAsync(null, DateTimeOffset.UtcNow));
    }

    [SkippableFact]
    public async Task Presenting_a_token_stamps_it_so_an_unused_one_is_visible()
    {
        Skip.IfNot(_fx.Available);

        // A minted-and-forgotten credential and a broken integration look the
        // same on the screen, and both are worth seeing.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var tokens = scope.ServiceProvider.GetRequiredService<McpTokenService>();

        var minted = await tokens.MintAsync(world.Admin, world.ProjectScope, "claude", null, 30);

        var before = (await tokens.ListAsync(world.ProjectScope, DateTimeOffset.UtcNow))
            .Single(t => t.Id == minted.Value!.Id);
        Assert.Null(before.LastUsedAt);

        await tokens.ResolveAsync(minted.Value!.Plaintext, DateTimeOffset.UtcNow);

        var after = (await tokens.ListAsync(world.ProjectScope, DateTimeOffset.UtcNow))
            .Single(t => t.Id == minted.Value.Id);
        Assert.NotNull(after.LastUsedAt);
    }

    // ---- Scoping: down, never up --------------------------------------------

    [SkippableFact]
    public async Task A_component_scoped_token_cannot_see_its_sibling()
    {
        Skip.IfNot(_fx.Available);

        // THE rule. A component-level token sees that component and nothing
        // beside it, however close the sibling sits in the tree.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var reads = scope.ServiceProvider.GetRequiredService<AgentReadService>();

        var page = await reads.FindingsAsync(Agent(world.ComponentScope), new AgentFindingsFilter());

        Assert.Equal(1, page.Total);
        Assert.Equal("alpha-rule", page.Findings.Single().RuleId);
    }

    [SkippableFact]
    public async Task A_project_scoped_token_sees_all_of_its_components()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var reads = scope.ServiceProvider.GetRequiredService<AgentReadService>();

        var page = await reads.FindingsAsync(Agent(world.ProjectScope), new AgentFindingsFilter());

        Assert.Equal(2, page.Total);
        Assert.Contains(page.Findings, f => f.RuleId == "alpha-rule");
        Assert.Contains(page.Findings, f => f.RuleId == "beta-rule");
    }

    [SkippableFact]
    public async Task A_client_scoped_token_sees_the_whole_tree_under_that_client()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var reads = scope.ServiceProvider.GetRequiredService<AgentReadService>();

        var page = await reads.FindingsAsync(Agent(world.ClientScope), new AgentFindingsFilter());

        Assert.Equal(3, page.Total);
        Assert.Contains(page.Findings, f => f.RuleId == "other-project-rule");
    }

    [SkippableFact]
    public async Task No_token_reaches_another_client()
    {
        Skip.IfNot(_fx.Available);

        // The one that matters on a multi-tenant deployment, and the one a
        // wrong join would break silently.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var reads = scope.ServiceProvider.GetRequiredService<AgentReadService>();

        var page = await reads.FindingsAsync(Agent(world.ClientScope), new AgentFindingsFilter());

        Assert.DoesNotContain(page.Findings, f => f.RuleId == "other-client-rule");
    }

    [SkippableFact]
    public async Task An_unscoped_identity_reads_nothing_rather_than_everything()
    {
        Skip.IfNot(_fx.Available);

        // A token that somehow reached the read surface with no scope must fail
        // closed. "No filter" and "no restriction" are one keystroke apart.
        await SeedAsync();
        using var scope = _fx.Scope();
        var reads = scope.ServiceProvider.GetRequiredService<AgentReadService>();

        var page = await reads.FindingsAsync(Agent(ScopeTarget.Instance), new AgentFindingsFilter());

        Assert.Equal(0, page.Total);
    }

    [SkippableFact]
    public async Task A_finding_outside_scope_is_not_found_rather_than_forbidden()
    {
        Skip.IfNot(_fx.Available);

        // Distinguishing them would confirm the existence of a finding the
        // caller may not see, which is the one bit this surface withholds.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var reads = scope.ServiceProvider.GetRequiredService<AgentReadService>();

        var mine = await reads.FindingAsync(Agent(world.ComponentScope), world.AlphaFindingId);
        var theirs = await reads.FindingAsync(Agent(world.ComponentScope), world.BetaFindingId);

        Assert.NotNull(mine);
        Assert.Null(theirs);
    }

    [SkippableFact]
    public async Task A_dependency_graph_outside_scope_is_not_returned()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var reads = scope.ServiceProvider.GetRequiredService<AgentReadService>();

        Assert.Null(await reads.DependenciesAsync(Agent(world.ComponentScope), world.BetaComponentId));
    }

    [SkippableFact]
    public async Task Suppression_state_outside_scope_is_not_returned()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var reads = scope.ServiceProvider.GetRequiredService<AgentReadService>();

        Assert.Null(await reads.SuppressionsAsync(
            Agent(world.ComponentScope), world.OtherProjectId, DateTimeOffset.UtcNow));
    }

    // ---- What the reads actually say ----------------------------------------

    [SkippableFact]
    public async Task The_scope_tool_names_the_hierarchy_rather_than_making_the_agent_guess()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var reads = scope.ServiceProvider.GetRequiredService<AgentReadService>();

        var tree = await reads.ScopeAsync(Agent(world.ProjectScope));

        var project = Assert.Single(tree);
        Assert.Equal(2, project.Components.Count);
    }

    [SkippableFact]
    public async Task A_truncated_page_reports_the_true_total()
    {
        Skip.IfNot(_fx.Available);

        // An agent that silently receives part of a list will confidently
        // report the part as the whole.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var reads = scope.ServiceProvider.GetRequiredService<AgentReadService>();

        var page = await reads.FindingsAsync(
            Agent(world.ClientScope), new AgentFindingsFilter(Limit: 1));

        Assert.Single(page.Findings);
        Assert.Equal(3, page.Total);
        Assert.True(page.Truncated);
    }

    [SkippableFact]
    public async Task Severity_filters_from_the_bottom_up()
    {
        Skip.IfNot(_fx.Available);

        // "Minimum severity: High" must mean High AND Critical, not High alone.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var reads = scope.ServiceProvider.GetRequiredService<AgentReadService>();

        var page = await reads.FindingsAsync(
            Agent(world.ClientScope), new AgentFindingsFilter(Severity: Severity.High));

        Assert.All(page.Findings, f => Assert.True(f.Severity >= Severity.High));
        Assert.Contains(page.Findings, f => f.Severity == Severity.Critical);
    }

    [SkippableFact]
    public async Task An_expired_suppression_is_returned_and_marked()
    {
        Skip.IfNot(_fx.Available);

        // A lapsed suppression is exactly the case where "why is this still
        // open" has a real answer.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var reads = scope.ServiceProvider.GetRequiredService<AgentReadService>();

        var state = await reads.SuppressionsAsync(
            Agent(world.ProjectScope), world.ProjectId, DateTimeOffset.UtcNow);

        var lapsed = Assert.Single(state!.Suppressions, s => s.Id == world.LapsedSuppressionId);
        Assert.True(lapsed.Expired);
    }

    [SkippableFact]
    public async Task A_component_scoped_suppression_carries_its_reason_and_author()
    {
        Skip.IfNot(_fx.Available);

        // The caller's own row. "Why is this muted" is the question the tool
        // exists to answer, and it is answered by the reason text.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var reads = scope.ServiceProvider.GetRequiredService<AgentReadService>();

        var state = await reads.SuppressionsAsync(
            Agent(world.ProjectScope), world.ProjectId, DateTimeOffset.UtcNow);

        var mine = Assert.Single(state!.Suppressions, s => s.Id == world.ComponentSuppressionId);
        Assert.False(mine.InstanceWide);
        Assert.Equal("Agent Minter", mine.Author);
        Assert.Contains("false positive", mine.Reason, StringComparison.Ordinal);
    }

    [SkippableFact]
    public async Task A_rule_scoped_suppression_is_surfaced_but_its_reason_is_withheld()
    {
        Skip.IfNot(_fx.Available);

        // A RuleEverywhere suppression carries no project — SuppressionMatcher
        // applies it globally — so it genuinely silences this project and must
        // be surfaced, or the agent would be told a finding is open that ingest
        // suppresses. What it must NOT leak is another tenant's reasoning.
        // TFND-132 covers the underlying model defect.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var reads = scope.ServiceProvider.GetRequiredService<AgentReadService>();

        var state = await reads.SuppressionsAsync(
            Agent(world.ProjectScope), world.ProjectId, DateTimeOffset.UtcNow);

        var lapsed = Assert.Single(state!.Suppressions, s => s.Id == world.LapsedSuppressionId);

        Assert.True(lapsed.InstanceWide);
        Assert.Equal("lapsed-rule", lapsed.RuleId);
        Assert.DoesNotContain("never revisited", lapsed.Reason, StringComparison.Ordinal);
        Assert.Equal("(withheld)", lapsed.Author);
    }

    [SkippableFact]
    public async Task Vex_statements_travel_with_the_suppressions()
    {
        Skip.IfNot(_fx.Available);

        // Both answer "has this already been decided". An agent that saw only
        // one would propose work that has already been declined.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var reads = scope.ServiceProvider.GetRequiredService<AgentReadService>();

        var state = await reads.SuppressionsAsync(
            Agent(world.ProjectScope), world.ProjectId, DateTimeOffset.UtcNow);

        Assert.Contains(state!.Vex, v => v.AdvisoryId == "CVE-2024-0001");
    }

    // ---- Audit ---------------------------------------------------------------

    [SkippableFact]
    public async Task Minting_and_revoking_are_recorded_as_access_decisions()
    {
        Skip.IfNot(_fx.Available);

        // A new way to read every finding in a scope is what an assessor reads
        // first.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var tokens = scope.ServiceProvider.GetRequiredService<McpTokenService>();
        var db = _fx.Db(scope);

        var minted = await tokens.MintAsync(world.Admin, world.ProjectScope, "claude", null, 30);
        await tokens.RevokeAsync(world.Admin, world.ProjectScope, minted.Value!.Id);

        var entries = await db.AuditEntries.AsNoTracking()
            .Where(a => a.SubjectId == minted.Value.Id)
            .ToArrayAsync();

        Assert.Equal(2, entries.Length);
        Assert.All(entries, e => Assert.Equal(AuditClass.Access, e.Class));
    }

    // ---- Helpers -------------------------------------------------------------

    /// <summary>
    /// An identity at a scope, with no role — the default an agent gets.
    ///
    /// Viewer is the ABSENCE of a grant, so this is the weakest thing that can
    /// still read evidence, which is what these scoping tests should exercise.
    /// </summary>
    private static AgentIdentity Agent(ScopeTarget scope) =>
        new(Guid.NewGuid(), "agent", Principal.For(Guid.Empty, "agent:test", false, []), scope);

    private sealed record World(
        Guid ClientId, Guid ProjectId, Guid OtherProjectId,
        Guid AlphaComponentId, Guid BetaComponentId,
        Guid AlphaFindingId, Guid BetaFindingId,
        Guid LapsedSuppressionId, Guid ComponentSuppressionId,
        ScopeTarget ClientScope, ScopeTarget ProjectScope, ScopeTarget ComponentScope,
        Principal Admin, Principal LeadDev);

    /// <summary>
    /// Two clients, two projects under the first, two components under the
    /// first project — one finding each, plus one under a different client.
    ///
    /// The shape is the point: every containment boundary the scoping rule
    /// draws has something on the far side of it to leak.
    /// </summary>
    private async Task<World> SeedAsync()
    {
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);

        var suffix = Guid.NewGuid().ToString("N")[..8];

        var client = new Client { Name = $"mcp-client-{suffix}" };
        var otherClient = new Client { Name = $"mcp-other-client-{suffix}" };

        var project = new Project { ClientId = client.Id, Name = $"mcp-project-{suffix}" };
        var otherProject = new Project { ClientId = client.Id, Name = $"mcp-other-project-{suffix}" };
        var foreignProject = new Project { ClientId = otherClient.Id, Name = $"mcp-foreign-{suffix}" };

        var alpha = new Component { ProjectId = project.Id, Name = "alpha" };
        var beta = new Component { ProjectId = project.Id, Name = "beta" };
        var otherComponent = new Component { ProjectId = otherProject.Id, Name = "gamma" };
        var foreignComponent = new Component { ProjectId = foreignProject.Id, Name = "delta" };

        db.Clients.AddRange(client, otherClient);
        db.Projects.AddRange(project, otherProject, foreignProject);
        db.Components.AddRange(alpha, beta, otherComponent, foreignComponent);

        var alphaFinding = Guid.NewGuid();
        var betaFinding = Guid.NewGuid();

        foreach (var (component, rule, severity, id) in new[]
        {
            (alpha, "alpha-rule", Severity.Critical, alphaFinding),
            (beta, "beta-rule", Severity.Low, betaFinding),
            (otherComponent, "other-project-rule", Severity.High, Guid.NewGuid()),
            (foreignComponent, "other-client-rule", Severity.Critical, Guid.NewGuid()),
        })
        {
            var version = new ComponentVersion
            {
                ComponentId = component.Id,
                VersionString = "1.0.0",
                CommitSha = suffix + "aaaaaa",
                BranchName = "main",
            };
            db.ComponentVersions.Add(version);

            db.Findings.Add(new Finding
            {
                Id = id,
                ComponentVersionId = version.Id,
                Hash = $"{rule}-{suffix}",
                Scanner = ScannerKind.OpenGrep,
                RuleId = rule,
                Severity = severity,
                Title = rule,
                FilePath = $"src/{component.Name}/Program.cs",
                Line = 10,
                Status = FindingStatus.Open,
            });
        }

        var user = new User
        {
            Login = $"mcp-{suffix}",
            DisplayName = "Agent Minter",
            Email = $"mcp-{suffix}@example.test",
            IsApproved = true,
        };
        db.Users.Add(user);

        // Rule-scoped: no project, no component. Instance-wide by construction.
        var lapsed = new Suppression
        {
            Scope = SuppressionScope.RuleEverywhere,
            RuleId = "lapsed-rule",
            CreatedByUserId = user.Id,
            CreatedByRole = ProjectRole.LeadDev,
            Reason = "Accepted for the release, then never revisited.",
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(-1),
        };

        // Component-scoped: anchored inside the caller's own tree.
        var anchored = new Suppression
        {
            Scope = SuppressionScope.RuleOnComponent,
            RuleId = "alpha-rule",
            ComponentId = alpha.Id,
            CreatedByUserId = user.Id,
            CreatedByRole = ProjectRole.LeadDev,
            Reason = "Reviewed and agreed to be a false positive on this component.",
        };

        db.Suppressions.AddRange(lapsed, anchored);

        db.VexStatements.Add(new VexStatement
        {
            ProjectId = project.Id,
            AdvisoryId = "CVE-2024-0001",
            Purl = "pkg:nuget/Example@1.0.0",
            Status = VexStatementStatus.NotAffected,
            Justification = VexJustification.VulnerableCodeNotInExecutePath,
            AuthorUserId = user.Id,
        });

        await db.SaveChangesAsync();

        return new World(
            client.Id, project.Id, otherProject.Id, alpha.Id, beta.Id, alphaFinding, betaFinding,
            lapsed.Id, anchored.Id,
            ScopeTarget.Client(client.Id),
            ScopeTarget.Project(client.Id, project.Id),
            ScopeTarget.Component(client.Id, project.Id, alpha.Id),
            Admin: Principal.For(user.Id, user.Login, isAdmin: true, []),
            LeadDev: Principal.For(user.Id, user.Login, isAdmin: false, [ProjectRole.LeadDev]));
    }
}
