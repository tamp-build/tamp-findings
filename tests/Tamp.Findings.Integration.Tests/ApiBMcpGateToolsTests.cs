using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Mcp;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;
using Tamp.Findings.Mcp;

namespace Tamp.Findings.Integration.Tests;

/// <summary>
/// The gate, score and build-history tools (TFND-236 / TFND-237).
///
/// Seeded with TWO canonical builds, because every claim these tools make that
/// is worth testing is a claim about the difference between them: which gate
/// blocks now, which way the score moved, and which findings the second commit
/// introduced. A one-build fixture would pass while attributing everything to
/// the only change it can see.
/// </summary>
[Collection(DatabaseCollection.Name)]
public class ApiBMcpGateToolsTests
{
    private readonly DatabaseFixture _fx;
    public ApiBMcpGateToolsTests(DatabaseFixture fx) => _fx = fx;

    private sealed record World(
        Guid ClientId, Guid ProjectId, Guid FreshProjectId, Guid ForeignProjectId,
        string PriorSha, string HeadSha, string CarriedHash, string IntroducedHash);

    /// <summary>
    /// One project with two canonical builds, one never-built project, and one
    /// under a different client.
    ///
    /// The older build carries one finding; the newer carries that same finding
    /// (same hash, so it is the same identity surviving) plus one the older
    /// build did not have. That shape is what separates "still open" from
    /// "this commit did it".
    /// </summary>
    private async Task<World> SeedAsync()
    {
        var s = ApiBSupport.Suffix();
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);

        var client = new Client { Name = $"apib-gate-{s}" };
        var otherClient = new Client { Name = $"apib-gate-o-{s}" };
        db.Clients.AddRange(client, otherClient);

        var project = new Project { ClientId = client.Id, Name = $"p-{s}" };
        var fresh = new Project { ClientId = client.Id, Name = $"fresh-{s}" };
        var foreign = new Project { ClientId = otherClient.Id, Name = $"f-{s}" };
        db.Projects.AddRange(project, fresh, foreign);

        var priorSha = $"{s}prior";
        var headSha = $"{s}head";

        // Ordered in time explicitly rather than relying on insertion order:
        // "the latest canonical build" is resolved by CreatedAt, and a fixture
        // whose builds share a timestamp would make the assertions coin flips.
        var prior = new ComponentVersion
        {
            ProjectId = project.Id, VersionString = "1.0.0", CommitSha = priorSha,
            BranchName = "main", CreatedAt = DateTimeOffset.UtcNow.AddDays(-2),
        };
        var head = new ComponentVersion
        {
            ProjectId = project.Id, VersionString = "1.1.0", CommitSha = headSha,
            BranchName = "main", CreatedAt = DateTimeOffset.UtcNow.AddHours(-1),
        };
        // A pull-request build, which is NOT canonical and must not become the
        // head the gate judges.
        var pr = new ComponentVersion
        {
            ProjectId = project.Id, VersionString = "1.2.0-pr", CommitSha = $"{s}pr",
            BranchName = "feature/x", PullRequestRef = "42", CreatedAt = DateTimeOffset.UtcNow,
        };
        db.ComponentVersions.AddRange(prior, head, pr);

        var carried = $"carried{s}";
        var introduced = $"introduced{s}";

        Finding F(Guid build, string hash, string rule, Severity sev, DateTimeOffset firstSeen) => new()
        {
            ComponentVersionId = build, Hash = hash, Scanner = ScannerKind.OpenGrep, RuleId = rule,
            Severity = sev, Title = rule, Description = "desc", FilePath = $"src/{rule}.cs", Line = 3,
            Snippet = "snip", FirstSeen = firstSeen, LastSeen = firstSeen,
        };

        // Same hash on both builds: one identity, surviving. Its FirstSeen on
        // the head row is recent, which is exactly the trap firstSeenInProject
        // exists to avoid.
        db.Findings.Add(F(prior.Id, carried, "carried", Severity.Critical, DateTimeOffset.UtcNow.AddDays(-2)));
        db.Findings.Add(F(head.Id, carried, "carried", Severity.Critical, DateTimeOffset.UtcNow.AddHours(-1)));
        db.Findings.Add(F(head.Id, introduced, "introduced", Severity.High, DateTimeOffset.UtcNow.AddHours(-1)));

        await db.SaveChangesAsync();

        return new World(
            client.Id, project.Id, fresh.Id, foreign.Id, priorSha, headSha, carried, introduced);
    }

    private static AgentIdentity Agent(ScopeTarget scope) =>
        new(Guid.NewGuid(), "agent", Principal.For(Guid.Empty, "agent:test", false, []), scope);

    private static JsonElement Json(object o) =>
        JsonSerializer.SerializeToElement(o, new JsonSerializerOptions(JsonSerializerDefaults.Web));

    private static (AgentReadService reads, AgentContext ctx) Services(IServiceScope scope, AgentIdentity identity)
    {
        var ctx = new AgentContext();
        ctx.Attach(identity);
        return (scope.ServiceProvider.GetRequiredService<AgentReadService>(), ctx);
    }

    // ---- get_gate -----------------------------------------------------------

    [SkippableFact]
    public async Task get_gate_judges_the_latest_canonical_build_and_names_it()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        using var scope = _fx.Scope();
        var (reads, ctx) = Services(scope, Agent(ScopeTarget.Project(w.ClientId, w.ProjectId)));

        var gate = Json(await FindingsTools.GetGateAsync(reads, ctx, w.ProjectId));

        // The head, not the PR build that was created more recently.
        Assert.Equal(w.HeadSha, gate.GetProperty("commitSha").GetString());
        Assert.NotEqual(JsonValueKind.Null, gate.GetProperty("enforcementMode").ValueKind);

        // Every row carries the evaluator's own text, so an agent and the CLI
        // describe one failure the same way.
        foreach (var row in gate.GetProperty("gates").EnumerateArray())
        {
            Assert.False(string.IsNullOrWhiteSpace(row.GetProperty("key").GetString()));
            Assert.False(string.IsNullOrWhiteSpace(row.GetProperty("verdict").GetString()));
            Assert.Equal(JsonValueKind.String, row.GetProperty("observed").ValueKind);
        }
    }

    [SkippableFact]
    public async Task get_gate_puts_the_blocking_rows_first()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        using var scope = _fx.Scope();
        var (reads, ctx) = Services(scope, Agent(ScopeTarget.Project(w.ClientId, w.ProjectId)));

        var gate = Json(await FindingsTools.GetGateAsync(reads, ctx, w.ProjectId));
        var blocks = gate.GetProperty("gates").EnumerateArray()
            .Select(r => r.GetProperty("blocks").GetBoolean())
            .ToArray();

        // The work comes first. Once a false appears, no true may follow it.
        Assert.DoesNotContain(false, blocks.TakeWhile(b => b).ToArray());
        Assert.Equal(blocks.OrderByDescending(b => b).ToArray(), blocks);
    }

    [SkippableFact]
    public async Task get_gate_agrees_with_the_gate_decision_service()
    {
        Skip.IfNot(_fx.Available);

        // The whole reason this read delegates. A verdict that disagreed with
        // the CLI gate's would be worse than no verdict, because an agent would
        // report it to somebody who then runs the CLI.
        var w = await SeedAsync();
        using var scope = _fx.Scope();
        var (reads, ctx) = Services(scope, Agent(ScopeTarget.Project(w.ClientId, w.ProjectId)));
        var decisions = scope.ServiceProvider
            .GetRequiredService<Tamp.Findings.Application.Risk.GateDecisionService>();

        var (status, canonical) = await decisions.ForLatestAsync(w.ProjectId);
        var gate = Json(await FindingsTools.GetGateAsync(reads, ctx, w.ProjectId));

        Assert.Equal(Tamp.Findings.Application.Risk.GateDecisionStatus.Ok, status);
        Assert.Equal(canonical!.Evaluation.ClearToShip, gate.GetProperty("clearToShip").GetBoolean());
        Assert.Equal(canonical.Evaluation.Blocking, gate.GetProperty("blocking").GetInt32());
        Assert.Equal(canonical.CurrentScore, gate.GetProperty("score").GetDouble());
        Assert.Equal(canonical.Evaluation.Enabled, gate.GetProperty("gates").GetArrayLength());
    }

    [SkippableFact]
    public async Task get_gate_on_a_never_built_project_says_so_instead_of_passing_it()
    {
        Skip.IfNot(_fx.Available);

        // The original four-valued-verdict bug, one layer up: a project nobody
        // has scanned must not read as clear.
        var w = await SeedAsync();
        using var scope = _fx.Scope();
        var (reads, ctx) = Services(scope, Agent(ScopeTarget.Client(w.ClientId)));

        var gate = Json(await FindingsTools.GetGateAsync(reads, ctx, w.FreshProjectId));

        Assert.False(gate.TryGetProperty("clearToShip", out _));
        Assert.Contains("no canonical build", gate.GetProperty("note").GetString(), StringComparison.Ordinal);
    }

    [SkippableFact]
    public async Task get_gate_refuses_a_project_outside_the_token_scope()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        using var scope = _fx.Scope();
        var (reads, ctx) = Services(scope, Agent(ScopeTarget.Project(w.ClientId, w.ProjectId)));

        var gate = Json(await FindingsTools.GetGateAsync(reads, ctx, w.ForeignProjectId));

        Assert.Contains("outside this token", gate.GetProperty("error").GetString(), StringComparison.Ordinal);
    }

    // ---- get_score ----------------------------------------------------------

    [SkippableFact]
    public async Task get_score_breaks_the_number_down_and_names_the_policy()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        using var scope = _fx.Scope();
        var (reads, ctx) = Services(scope, Agent(ScopeTarget.Project(w.ClientId, w.ProjectId)));

        var score = Json(await FindingsTools.GetScoreAsync(reads, ctx, w.ProjectId));

        Assert.True(score.GetProperty("score").GetDouble() >= 0);
        Assert.False(string.IsNullOrWhiteSpace(score.GetProperty("band").GetString()));
        // Named, so an agent quotes this instance's policy rather than implying
        // a universal scale.
        Assert.False(string.IsNullOrWhiteSpace(score.GetProperty("policyName").GetString()));
        Assert.True(score.GetProperty("categories").GetArrayLength() > 0);

        // Disabled categories are reported as disabled rather than omitted:
        // "not scored here" and "scored zero" lead to opposite advice.
        var hasEnabledFlag = score.GetProperty("categories").EnumerateArray()
            .All(c => c.TryGetProperty("enabled", out _));
        Assert.True(hasEnabledFlag);
    }

    [SkippableFact]
    public async Task get_score_contributions_are_ordered_by_where_the_work_is()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        using var scope = _fx.Scope();
        var (reads, ctx) = Services(scope, Agent(ScopeTarget.Project(w.ClientId, w.ProjectId)));

        var score = Json(await FindingsTools.GetScoreAsync(reads, ctx, w.ProjectId));
        var contributions = score.GetProperty("categories").EnumerateArray()
            .Select(c => c.GetProperty("contribution").GetDouble())
            .ToArray();

        Assert.Equal(contributions.OrderByDescending(x => x).ToArray(), contributions);
    }

    [SkippableFact]
    public async Task get_score_on_a_never_built_project_is_unscored_not_zero()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        using var scope = _fx.Scope();
        var (reads, ctx) = Services(scope, Agent(ScopeTarget.Client(w.ClientId)));

        var score = Json(await FindingsTools.GetScoreAsync(reads, ctx, w.FreshProjectId));

        Assert.False(score.TryGetProperty("score", out _));
        Assert.Contains("not a score of zero", score.GetProperty("note").GetString(), StringComparison.Ordinal);
    }

    // ---- list_builds --------------------------------------------------------

    [SkippableFact]
    public async Task list_builds_returns_canonical_builds_newest_first_and_excludes_pr_builds()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        using var scope = _fx.Scope();
        var (reads, ctx) = Services(scope, Agent(ScopeTarget.Project(w.ClientId, w.ProjectId)));

        var history = Json(await FindingsTools.ListBuildsAsync(reads, ctx, w.ProjectId));
        var shas = history.GetProperty("builds").EnumerateArray()
            .Select(b => b.GetProperty("commitSha").GetString() ?? "")
            .ToArray();

        Assert.Equal(new[] { w.HeadSha, w.PriorSha }, shas);
        Assert.DoesNotContain(shas, s => s.EndsWith("pr", StringComparison.Ordinal));
    }

    [SkippableFact]
    public async Task list_builds_on_a_never_built_project_explains_the_empty_history()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        using var scope = _fx.Scope();
        var (reads, ctx) = Services(scope, Agent(ScopeTarget.Client(w.ClientId)));

        var history = Json(await FindingsTools.ListBuildsAsync(reads, ctx, w.FreshProjectId));

        Assert.Contains("no canonical build", history.GetProperty("note").GetString(), StringComparison.Ordinal);
    }

    // ---- temporal signals on get_findings -----------------------------------

    [SkippableFact]
    public async Task get_findings_separates_a_findings_real_age_from_this_builds_sighting()
    {
        Skip.IfNot(_fx.Available);

        // The trap: ingest keys findings per (build, scanner), so the carried
        // finding has a fresh FirstSeen on the head build even though it is two
        // days old. Reported as "open since", that makes old problems look new.
        var w = await SeedAsync();
        using var scope = _fx.Scope();
        var (reads, ctx) = Services(scope, Agent(ScopeTarget.Project(w.ClientId, w.ProjectId)));

        var page = Json(await FindingsTools.GetFindingsAsync(reads, ctx));
        var carried = page.GetProperty("findings").EnumerateArray()
            .First(f => f.GetProperty("ruleId").GetString() == "carried");

        var firstSeen = carried.GetProperty("firstSeen").GetDateTimeOffset();
        var age = carried.GetProperty("firstSeenInProject").GetDateTimeOffset();

        Assert.True(age < firstSeen, "the project-wide age must predate this build's sighting");
        Assert.True(age < DateTimeOffset.UtcNow.AddDays(-1), "the carried finding is two days old");
    }

    [SkippableFact]
    public async Task get_findings_counts_a_surviving_finding_once_not_once_per_build()
    {
        Skip.IfNot(_fx.Available);

        // TFND-243. Findings are per-build rows and the auto-close sweep only
        // touches the build being ingested, so the carried finding has an Open
        // row on BOTH builds. Unscoped, this answered "three open findings" for
        // a project with two, and repeated one of them under two ids.
        var w = await SeedAsync();
        using var scope = _fx.Scope();
        var (reads, ctx) = Services(scope, Agent(ScopeTarget.Project(w.ClientId, w.ProjectId)));

        var page = Json(await FindingsTools.GetFindingsAsync(reads, ctx));
        var rules = page.GetProperty("findings").EnumerateArray()
            .Select(f => f.GetProperty("ruleId").GetString() ?? "")
            .ToArray();

        Assert.Equal(2, page.GetProperty("total").GetInt32());
        Assert.Equal(new[] { "carried", "introduced" }, rules.OrderBy(r => r, StringComparer.Ordinal).ToArray());
    }

    [SkippableFact]
    public async Task get_findings_still_answers_about_a_named_commit()
    {
        Skip.IfNot(_fx.Available);

        // The build scoping is a default, not a restriction: naming the prior
        // commit must still return that build's findings, or there would be no
        // way to ask what an older build looked like.
        var w = await SeedAsync();
        using var scope = _fx.Scope();
        var (reads, ctx) = Services(scope, Agent(ScopeTarget.Project(w.ClientId, w.ProjectId)));

        var page = Json(await FindingsTools.GetFindingsAsync(reads, ctx, commitSha: w.PriorSha));
        var rules = page.GetProperty("findings").EnumerateArray()
            .Select(f => f.GetProperty("ruleId").GetString() ?? "")
            .ToArray();

        Assert.Equal(new[] { "carried" }, rules);
    }

    [SkippableFact]
    public async Task get_findings_anchors_attribution_on_the_commit_it_was_asked_about()
    {
        Skip.IfNot(_fx.Available);

        // The prior build is the project's OLDEST canonical build, so there is
        // nothing before it to diff against and attribution must be null.
        //
        // The bug this guards: anchoring on the head's predecessor regardless of
        // what was asked. Asked about the prior commit, that compares the build
        // with itself and reports every finding as not-introduced — false rather
        // than null, which is a claim instead of an absence of one.
        var w = await SeedAsync();
        using var scope = _fx.Scope();
        var (reads, ctx) = Services(scope, Agent(ScopeTarget.Project(w.ClientId, w.ProjectId)));

        var page = Json(await FindingsTools.GetFindingsAsync(reads, ctx, commitSha: w.PriorSha));
        var carried = page.GetProperty("findings")[0];

        Assert.Equal(JsonValueKind.Null, carried.GetProperty("introducedInThisBuild").ValueKind);
    }

    [SkippableFact]
    public async Task get_findings_refuses_to_attribute_a_pull_request_build()
    {
        Skip.IfNot(_fx.Available);

        // A PR build has no "build before it" on main, so attributing it
        // against main's history would credit the branch with whatever main
        // happened to fix. Null, not false.
        var s = ApiBSupport.Suffix();
        Guid clientId, projectId;
        string prSha;

        using (var seed = _fx.Scope())
        {
            var db = _fx.Db(seed);
            var client = new Client { Name = $"apib-pr-{s}" };
            db.Clients.Add(client);
            var project = new Project { ClientId = client.Id, Name = $"pr-{s}" };
            db.Projects.Add(project);

            var main = new ComponentVersion
            {
                ProjectId = project.Id, VersionString = "1.0.0", CommitSha = $"{s}main",
                BranchName = "main", CreatedAt = DateTimeOffset.UtcNow.AddDays(-1),
            };
            prSha = $"{s}pr";
            var pr = new ComponentVersion
            {
                ProjectId = project.Id, VersionString = "1.1.0", CommitSha = prSha,
                BranchName = "feature/y", PullRequestRef = "7", CreatedAt = DateTimeOffset.UtcNow,
            };
            db.ComponentVersions.AddRange(main, pr);
            db.Findings.Add(new Finding
            {
                ComponentVersionId = pr.Id, Hash = $"onbranch{s}", Scanner = ScannerKind.OpenGrep,
                RuleId = "onbranch", Severity = Severity.High, Title = "onbranch",
                FilePath = "b.cs", Line = 1,
            });
            await db.SaveChangesAsync();
            clientId = client.Id;
            projectId = project.Id;
        }

        using var scope = _fx.Scope();
        var (reads, ctx) = Services(scope, Agent(ScopeTarget.Project(clientId, projectId)));

        var page = Json(await FindingsTools.GetFindingsAsync(reads, ctx, commitSha: prSha));
        var onBranch = page.GetProperty("findings")[0];

        Assert.Equal("onbranch", onBranch.GetProperty("ruleId").GetString());
        Assert.Equal(JsonValueKind.Null, onBranch.GetProperty("introducedInThisBuild").ValueKind);
    }

    [SkippableFact]
    public async Task get_findings_attributes_only_the_finding_the_head_build_introduced()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        using var scope = _fx.Scope();
        var (reads, ctx) = Services(scope, Agent(ScopeTarget.Project(w.ClientId, w.ProjectId)));

        var page = Json(await FindingsTools.GetFindingsAsync(reads, ctx));
        var byRule = page.GetProperty("findings").EnumerateArray()
            .ToDictionary(f => f.GetProperty("ruleId").GetString()!, f => f);

        Assert.True(byRule["introduced"].GetProperty("introducedInThisBuild").GetBoolean());
        Assert.False(byRule["carried"].GetProperty("introducedInThisBuild").GetBoolean());
    }

    [SkippableFact]
    public async Task get_findings_will_not_attribute_anything_on_a_projects_first_build()
    {
        Skip.IfNot(_fx.Available);

        // With no prior canonical build there is nothing to diff against, and
        // "false" would be a claim this surface cannot support — so null.
        var s = ApiBSupport.Suffix();
        using (var seed = _fx.Scope())
        {
            var db = _fx.Db(seed);
            var client = new Client { Name = $"apib-first-{s}" };
            db.Clients.Add(client);
            var project = new Project { ClientId = client.Id, Name = $"only-{s}" };
            db.Projects.Add(project);
            var only = new ComponentVersion
            {
                ProjectId = project.Id, VersionString = "1.0.0", CommitSha = $"{s}only",
                BranchName = "main",
            };
            db.ComponentVersions.Add(only);
            db.Findings.Add(new Finding
            {
                ComponentVersionId = only.Id, Hash = $"first{s}", Scanner = ScannerKind.OpenGrep,
                RuleId = "first", Severity = Severity.High, Title = "first", FilePath = "a.cs", Line = 1,
            });
            await db.SaveChangesAsync();

            using var scope = _fx.Scope();
            var (reads, ctx) = Services(scope, Agent(ScopeTarget.Project(client.Id, project.Id)));

            var page = Json(await FindingsTools.GetFindingsAsync(reads, ctx));
            var only1 = page.GetProperty("findings")[0];

            Assert.Equal(JsonValueKind.Null, only1.GetProperty("introducedInThisBuild").ValueKind);
        }
    }
}
