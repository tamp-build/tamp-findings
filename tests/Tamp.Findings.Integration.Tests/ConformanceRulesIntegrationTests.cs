using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Compliance;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Integration.Tests;

// TFND-190 / ADR 0012: the authoritative conformance-rules store. A generation-push
// replaces a project's active rule set (upsert + retire-missing, never hard-delete); the
// ruleset-fetch serves the active set the analyzer runs.
[Collection(DatabaseCollection.Name)]
public class ConformanceRulesIntegrationTests
{
    private readonly DatabaseFixture _fx;
    public ConformanceRulesIntegrationTests(DatabaseFixture fx) => _fx = fx;

    private async Task<Guid> NewProjectAsync()
    {
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var s = Guid.NewGuid().ToString("N")[..8];
        var client = new Client { Name = $"rc-{s}" };
        db.Clients.Add(client);
        var project = new Project { ClientId = client.Id, Name = $"rp-{s}" };
        db.Projects.Add(project);
        await db.SaveChangesAsync();
        return project.Id;
    }

    private static AdrRuleDto Rule(string adr, string id, string method = "deterministic", string review = "Reviewed") =>
        new() { AdrRef = adr, RuleId = id, Intent = $"{id} intent", Method = method, CheckSpec = $"spec:{id}",
                ControlRefs = ["CM-6"], ReviewStatus = review };

    [SkippableFact]
    public async Task Push_then_fetch_returns_the_active_set()
    {
        Skip.IfNot(_fx.Available);
        var projectId = await NewProjectAsync();

        using (var scope = _fx.Scope())
        {
            var svc = scope.ServiceProvider.GetRequiredService<ConformanceRulesService>();
            var r = await svc.PushAsync(projectId, new AdrRuleGeneration
            {
                GenerationSha = "gen1", ExtractionModelId = "m1",
                Rules = [ Rule("ADR 1", "a"), Rule("ADR 1", "b", method: "semantic") ],
            });
            Assert.Equal(2, r.Upserted);
            Assert.Equal(0, r.Retired);
            Assert.Equal(2, r.Active);
        }

        using (var scope = _fx.Scope())
        {
            var q = scope.ServiceProvider.GetRequiredService<ConformanceRulesQuery>();
            var set = await q.ForProjectAsync(projectId);
            Assert.Equal(2, set.Rules.Count);
            var a = set.Rules.Single(x => x.RuleId == "a");
            Assert.Equal("spec:a", a.CheckSpec);
            Assert.Equal("Deterministic", a.Method);
            Assert.Contains("CM-6", a.ControlRefs);
            Assert.Equal("Reviewed", a.ReviewStatus);
            Assert.Equal("Semantic", set.Rules.Single(x => x.RuleId == "b").Method);
        }
    }

    [SkippableFact]
    public async Task Re_push_retires_dropped_rules_and_never_hard_deletes()
    {
        Skip.IfNot(_fx.Available);
        var projectId = await NewProjectAsync();

        using (var scope = _fx.Scope())
        {
            var svc = scope.ServiceProvider.GetRequiredService<ConformanceRulesService>();
            await svc.PushAsync(projectId, new AdrRuleGeneration { GenerationSha = "g1",
                Rules = [ Rule("ADR 1", "a"), Rule("ADR 1", "b") ] });

            // Second generation drops "b", keeps "a" (updated), adds "c".
            var r = await svc.PushAsync(projectId, new AdrRuleGeneration { GenerationSha = "g2",
                Rules = [ Rule("ADR 1", "a"), Rule("ADR 2", "c") ] });
            Assert.Equal(2, r.Upserted);   // a (update) + c (new)
            Assert.Equal(1, r.Retired);    // b
            Assert.Equal(2, r.Active);
        }

        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            // "b" is retired, NOT deleted (a past verdict can still cite it).
            var b = await db.ConformanceRules.SingleAsync(r => r.ProjectId == projectId && r.RuleId == "b");
            Assert.NotNull(b.RetiredAt);
            Assert.Equal(3, await db.ConformanceRules.CountAsync(r => r.ProjectId == projectId)); // a, b(retired), c

            var q = scope.ServiceProvider.GetRequiredService<ConformanceRulesQuery>();
            var set = await q.ForProjectAsync(projectId);
            Assert.Equal(2, set.Rules.Count);   // active: a, c
            Assert.DoesNotContain(set.Rules, x => x.RuleId == "b");
        }
    }

    [SkippableFact]
    public async Task Re_pushing_a_previously_retired_rule_reactivates_it()
    {
        Skip.IfNot(_fx.Available);
        var projectId = await NewProjectAsync();

        using (var scope = _fx.Scope())
        {
            var s = scope.ServiceProvider.GetRequiredService<ConformanceRulesService>();
            await s.PushAsync(projectId, new AdrRuleGeneration { Rules = [ Rule("ADR 1", "a") ] });
            await s.PushAsync(projectId, new AdrRuleGeneration { Rules = [ Rule("ADR 1", "b") ] }); // retires a
            var r = await s.PushAsync(projectId, new AdrRuleGeneration { Rules = [ Rule("ADR 1", "a") ] }); // brings a back
            Assert.Equal(1, r.Active);
        }
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            var a = await db.ConformanceRules.SingleAsync(r => r.ProjectId == projectId && r.RuleId == "a");
            Assert.Null(a.RetiredAt);   // reactivated (still one row — upsert, not duplicate)
            Assert.Equal(1, await db.ConformanceRules.CountAsync(r => r.ProjectId == projectId && r.RuleId == "a"));
        }
    }
}
