using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Compliance;
using Tamp.Findings.Domain.Compliance;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Integration.Tests;

// TFND-191 / ADR 0006: the review-gating that turns ADR-conformance into a go/no-go —
// human-first. A finding blocks ONLY when undispositioned, its rule is Reviewed, and (for
// Semantic) verify-Confirmed. Plus the VEX-accept write-path clearing a block.
[Collection(DatabaseCollection.Name)]
public class ConformanceGateIntegrationTests
{
    private readonly DatabaseFixture _fx;
    public ConformanceGateIntegrationTests(DatabaseFixture fx) => _fx = fx;

    private sealed record World(Guid ProjectId, Guid ClientId, Guid CvId, Guid UserId, string UserLogin);

    private async Task<World> SeedAsync()
    {
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var s = Guid.NewGuid().ToString("N")[..8];
        var user = new User { Login = $"cg-{s}", DisplayName = "cg", Email = $"cg{s}@e.test", IsApproved = true };
        db.Users.Add(user);
        var client = new Client { Name = $"cgc-{s}" };
        db.Clients.Add(client);
        var project = new Project { ClientId = client.Id, Name = $"cgp-{s}" };
        db.Projects.Add(project);
        var comp = new Component { ProjectId = project.Id, Name = "svc" };
        db.Components.Add(comp);
        var cv = new ComponentVersion { ProjectId = comp.ProjectId, ComponentId = comp.Id, VersionString = "1.0.0", CommitSha = $"sha{s}" };
        db.ComponentVersions.Add(cv);
        await db.SaveChangesAsync();
        return new World(project.Id, client.Id, cv.Id, user.Id, user.Login);
    }

    private static void AddRule(Data.FindingsDbContext db, Guid projectId, string adr, string rule, ReviewStatus review)
        => db.ConformanceRules.Add(new ConformanceRule { ProjectId = projectId, AdrRef = adr, RuleId = rule, ReviewStatus = review });

    private static void AddFinding(Data.FindingsDbContext db, Guid cvId, string adr, string rule,
        ConformanceVerdict verdict, ConformanceMethod method = ConformanceMethod.Deterministic,
        VerifyOutcome verify = VerifyOutcome.NotRun, bool dispositioned = false)
        => db.ConformanceFindings.Add(new ConformanceFinding
        {
            ComponentVersionId = cvId, AdrRef = adr, RuleId = rule, Claim = rule,
            Verdict = verdict, Method = method, VerifyVerdict = verify,
            Dispositioned = dispositioned, DispositionJustification = dispositioned ? "accepted" : null,
        });

    [SkippableFact]
    public async Task Only_reviewed_undispositioned_verified_findings_count()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();

        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            // Rules: r1-r7 Reviewed, rDraft Draft; rNone has no rule row.
            foreach (var r in new[] { "r1", "r2", "r3", "r4", "r5", "r6", "r7" })
                AddRule(db, w.ProjectId, "ADR 1", r, ReviewStatus.Reviewed);
            AddRule(db, w.ProjectId, "ADR 1", "rDraft", ReviewStatus.Draft);

            AddFinding(db, w.CvId, "ADR 1", "r1", ConformanceVerdict.Fail);                                   // COUNTS (fail)
            AddFinding(db, w.CvId, "ADR 1", "rDraft", ConformanceVerdict.Fail);                                // no (draft rule)
            AddFinding(db, w.CvId, "ADR 1", "r2", ConformanceVerdict.Fail, dispositioned: true);              // no (accepted)
            AddFinding(db, w.CvId, "ADR 1", "r3", ConformanceVerdict.Fail, ConformanceMethod.Semantic, VerifyOutcome.NotRun);   // no (unconfirmed semantic)
            AddFinding(db, w.CvId, "ADR 1", "r4", ConformanceVerdict.Fail, ConformanceMethod.Semantic, VerifyOutcome.Confirmed);// COUNTS (fail, confirmed)
            AddFinding(db, w.CvId, "ADR 1", "r5", ConformanceVerdict.Unknown);                                 // COUNTS (unknown)
            AddFinding(db, w.CvId, "ADR 1", "r6", ConformanceVerdict.Pass);                                    // no (pass)
            AddFinding(db, w.CvId, "ADR 1", "rNone", ConformanceVerdict.Fail);                                 // no (no rule)
            await db.SaveChangesAsync();
        }

        using (var scope = _fx.Scope())
        {
            var q = scope.ServiceProvider.GetRequiredService<ConformanceGateQuery>();
            var sum = await q.ForBuildAsync(w.ProjectId, new[] { w.CvId }, DateTimeOffset.UtcNow);
            Assert.Equal(8, sum.Evaluated);       // all findings counted in the denominator
            Assert.Equal(2, sum.BlockingFails);   // r1 + r4
            Assert.Equal(1, sum.BlockingUnknowns);// r5
        }
    }

    [SkippableFact]
    public async Task Vex_accept_clears_the_block_and_requires_accept_risk()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        Guid findingId;
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            AddRule(db, w.ProjectId, "ADR 5", "secret", ReviewStatus.Reviewed);
            var f = new ConformanceFinding { ComponentVersionId = w.CvId, AdrRef = "ADR 5", RuleId = "secret",
                Claim = "secret", Verdict = ConformanceVerdict.Fail, Method = ConformanceMethod.Deterministic };
            db.ConformanceFindings.Add(f);
            await db.SaveChangesAsync();
            findingId = f.Id;
        }

        // Blocks before disposition.
        using (var scope = _fx.Scope())
        {
            var q = scope.ServiceProvider.GetRequiredService<ConformanceGateQuery>();
            Assert.Equal(1, (await q.ForBuildAsync(w.ProjectId, new[] { w.CvId }, DateTimeOffset.UtcNow)).BlockingFails);
        }

        var scopeTarget = ScopeTarget.Project(w.ClientId, w.ProjectId);

        // A Viewer (no AcceptRisk) is denied.
        using (var scope = _fx.Scope())
        {
            var svc = scope.ServiceProvider.GetRequiredService<ConformanceDispositionService>();
            var viewer = Principal.For(w.UserId, w.UserLogin, isAdmin: false, []);
            var denied = await svc.DisposeAsync(viewer, scopeTarget, w.ProjectId, findingId, "waive", null);
            Assert.False(denied.Success);
            Assert.True(denied.WasDenied);
        }

        // InfoSec (AcceptRisk) accepts it.
        using (var scope = _fx.Scope())
        {
            var svc = scope.ServiceProvider.GetRequiredService<ConformanceDispositionService>();
            var infosec = Principal.For(w.UserId, w.UserLogin, isAdmin: false, [ProjectRole.InfoSecOfficer]);
            var ok = await svc.DisposeAsync(infosec, scopeTarget, w.ProjectId, findingId, "risk accepted by AO", null);
            Assert.True(ok.Success, ok.Error);
        }

        // No longer blocks.
        using (var scope = _fx.Scope())
        {
            var q = scope.ServiceProvider.GetRequiredService<ConformanceGateQuery>();
            Assert.Equal(0, (await q.ForBuildAsync(w.ProjectId, new[] { w.CvId }, DateTimeOffset.UtcNow)).BlockingFails);
        }
    }
}
