using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Compliance;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

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
    public async Task Review_promotes_rules_and_requires_edit_gates()
    {
        Skip.IfNot(_fx.Available);
        var s = Guid.NewGuid().ToString("N")[..8];
        Guid projectId, clientId, userId; string login;
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            var user = new User { Login = $"rr-{s}", DisplayName = "rr", Email = $"rr{s}@e.test", IsApproved = true };
            db.Users.Add(user);
            var client = new Client { Name = $"rrc-{s}" };
            db.Clients.Add(client);
            var project = new Project { ClientId = client.Id, Name = $"rrp-{s}" };
            db.Projects.Add(project);
            await db.SaveChangesAsync();
            (projectId, clientId, userId, login) = (project.Id, client.Id, user.Id, user.Login);

            // Push two Draft rules.
            var svc = scope.ServiceProvider.GetRequiredService<ConformanceRulesService>();
            await svc.PushAsync(projectId, new AdrRuleGeneration
            {
                Rules = [ Rule("ADR 1", "a", review: "Draft"), Rule("ADR 1", "b", review: "Draft") ],
            });
        }

        var target = ScopeTarget.Project(clientId, projectId);

        // A Viewer cannot review (EditGates is Admin + InfoSec).
        using (var scope = _fx.Scope())
        {
            var svc = scope.ServiceProvider.GetRequiredService<ConformanceRulesService>();
            var viewer = Principal.For(userId, login, isAdmin: false, []);
            var denied = await svc.SetReviewStatusAsync(viewer, target, projectId, "ADR 1", "a", ReviewStatus.Reviewed);
            Assert.False(denied.Success);
            Assert.True(denied.WasDenied);
        }

        // InfoSec promotes one rule, then bulk-promotes the rest.
        using (var scope = _fx.Scope())
        {
            var svc = scope.ServiceProvider.GetRequiredService<ConformanceRulesService>();
            var infosec = Principal.For(userId, login, isAdmin: false, [ProjectRole.InfoSecOfficer]);
            Assert.True((await svc.SetReviewStatusAsync(infosec, target, projectId, "ADR 1", "a", ReviewStatus.Reviewed)).Success);
            var bulk = await svc.PromoteDraftAsync(infosec, target, projectId, null);
            Assert.True(bulk.Success);
            Assert.Equal(1, bulk.Value);   // only "b" was still Draft
        }

        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            Assert.Equal(2, await db.ConformanceRules.CountAsync(r => r.ProjectId == projectId && r.ReviewStatus == ReviewStatus.Reviewed));
            Assert.Equal(0, await db.ConformanceRules.CountAsync(r => r.ProjectId == projectId && r.ReviewStatus == ReviewStatus.Draft));
        }
    }

    // TFND-196: a content change at the same key invalidates the human review — the rule is
    // forced back to Draft (the DTO cannot self-certify a regenerated check as Reviewed), and
    // the open mandate POA&M it had raised is auto-superseded with an audited reason.
    [SkippableFact]
    public async Task Content_change_forces_draft_and_supersedes_the_mandate_poam()
    {
        Skip.IfNot(_fx.Available);
        var s = Guid.NewGuid().ToString("N")[..8];
        Guid projectId, userId;
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            var user = new User { Login = $"su-{s}", DisplayName = "su", Email = $"su{s}@e.test", IsApproved = true };
            db.Users.Add(user);
            var client = new Client { Name = $"suc-{s}" };
            db.Clients.Add(client);
            var project = new Project { ClientId = client.Id, Name = $"sup-{s}" };
            db.Projects.Add(project);
            await db.SaveChangesAsync();
            (projectId, userId) = (project.Id, user.Id);

            var svc = scope.ServiceProvider.GetRequiredService<ConformanceRulesService>();
            await svc.PushAsync(projectId, new AdrRuleGeneration
            {
                GenerationSha = "gen-A",
                Rules = [ new AdrRuleDto { AdrRef = "ADR 1", RuleId = "m", Intent = "logging maturity",
                    Method = "deterministic", CheckSpec = "spec:v1", ControlRefs = ["AU-2"],
                    MandateId = "M-1", ReviewStatus = "Reviewed" } ],
            });

            // The reconciler would have raised this; seed it directly to test the close path.
            db.PoamItems.Add(new PoamItem
            {
                ProjectId = projectId, Title = "Mandate not met: M-1",
                WeaknessDescription = "The 'M-1' mandate is Unknown on the latest build.",
                Severity = Severity.Medium, Status = PoamStatus.Open,
                SourceKind = PoamSource.OperationalMandate, SourceRef = "M-1", AuthorUserId = userId,
            });
            await db.SaveChangesAsync();
        }

        RulesPushResult push;
        using (var scope = _fx.Scope())
        {
            var svc = scope.ServiceProvider.GetRequiredService<ConformanceRulesService>();
            // Same key, changed CheckSpec, and a NEW generation sha — the DTO still claims Reviewed.
            push = await svc.PushAsync(projectId, new AdrRuleGeneration
            {
                GenerationSha = "gen-B",
                Rules = [ new AdrRuleDto { AdrRef = "ADR 1", RuleId = "m", Intent = "logging maturity",
                    Method = "deterministic", CheckSpec = "spec:v2", ControlRefs = ["AU-2"],
                    MandateId = "M-1", ReviewStatus = "Reviewed" } ],
            });
        }

        Assert.Single(push.Superseded);
        Assert.Equal("M-1", push.Superseded[0].MandateId);

        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            var rule = await db.ConformanceRules.SingleAsync(r => r.ProjectId == projectId && r.RuleId == "m");
            Assert.Equal(ReviewStatus.Draft, rule.ReviewStatus);   // review invalidated by the change

            var poam = await db.PoamItems.SingleAsync(p => p.ProjectId == projectId && p.SourceRef == "M-1");
            Assert.Equal(PoamStatus.Cancelled, poam.Status);
            Assert.NotNull(poam.ClosedAt);
            Assert.Contains("Superseded", poam.WeaknessDescription);

            Assert.Equal(1, await db.AuditEntries.CountAsync(e => e.ProjectId == projectId && e.Action == "poam.superseded"));
        }
    }

    // The complement: an identical re-push (new generation sha, same content) is a no-op for
    // review — the human's Reviewed stands and the POA&M stays open.
    [SkippableFact]
    public async Task Unchanged_repush_keeps_review_and_leaves_the_poam_open()
    {
        Skip.IfNot(_fx.Available);
        var s = Guid.NewGuid().ToString("N")[..8];
        Guid projectId, userId;
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            var user = new User { Login = $"nk-{s}", DisplayName = "nk", Email = $"nk{s}@e.test", IsApproved = true };
            db.Users.Add(user);
            var client = new Client { Name = $"nkc-{s}" };
            db.Clients.Add(client);
            var project = new Project { ClientId = client.Id, Name = $"nkp-{s}" };
            db.Projects.Add(project);
            await db.SaveChangesAsync();
            (projectId, userId) = (project.Id, user.Id);

            var svc = scope.ServiceProvider.GetRequiredService<ConformanceRulesService>();
            AdrRuleDto Rule() => new() { AdrRef = "ADR 1", RuleId = "m", Intent = "logging maturity",
                Method = "deterministic", CheckSpec = "spec:v1", ControlRefs = ["AU-2"],
                MandateId = "M-1", ReviewStatus = "Reviewed" };
            await svc.PushAsync(projectId, new AdrRuleGeneration { GenerationSha = "gen-A", Rules = [ Rule() ] });

            db.PoamItems.Add(new PoamItem
            {
                ProjectId = projectId, Title = "Mandate not met: M-1",
                WeaknessDescription = "The 'M-1' mandate is Unknown on the latest build.",
                Severity = Severity.Medium, Status = PoamStatus.Open,
                SourceKind = PoamSource.OperationalMandate, SourceRef = "M-1", AuthorUserId = userId,
            });
            await db.SaveChangesAsync();

            // Re-push identical content under a different generation sha.
            var push = await svc.PushAsync(projectId, new AdrRuleGeneration { GenerationSha = "gen-B", Rules = [ Rule() ] });
            Assert.Empty(push.Superseded);
        }

        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            var rule = await db.ConformanceRules.SingleAsync(r => r.ProjectId == projectId && r.RuleId == "m");
            Assert.Equal(ReviewStatus.Reviewed, rule.ReviewStatus);   // review preserved
            var poam = await db.PoamItems.SingleAsync(p => p.ProjectId == projectId && p.SourceRef == "M-1");
            Assert.Equal(PoamStatus.Open, poam.Status);              // still tracked
            Assert.Null(poam.ClosedAt);
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
