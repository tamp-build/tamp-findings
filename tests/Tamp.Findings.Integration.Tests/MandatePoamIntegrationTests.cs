using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Zt;
using Tamp.Findings.Domain.Compliance;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Integration.Tests;

// TFND-189 / ADR 0010 §7,§9: a failing/unproven mandate becomes a dated POA&M in the
// shared model, idempotently, with the deadline from the effective policy window.
[Collection(DatabaseCollection.Name)]
public class MandatePoamIntegrationTests
{
    private readonly DatabaseFixture _fx;
    public MandatePoamIntegrationTests(DatabaseFixture fx) => _fx = fx;

    private async Task<(Guid projectId, Guid userId)> SeedAsync(params (string MandateId, ConformanceVerdict Verdict)[] mandates)
    {
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var s = Guid.NewGuid().ToString("N")[..8];

        // FedRAMP High has a POA&M deadline window (Critical/High 30d, Medium 90d).
        var tplId = await db.PolicyTemplates.Where(t => t.Name == "FedRAMP High").Select(t => (Guid?)t.Id).FirstAsync();
        var user = new User { Login = $"mp-{s}", DisplayName = "mp", Email = $"mp{s}@e.test", IsApproved = true };
        db.Users.Add(user);
        var client = new Client { Name = $"mpc-{s}", PolicyTemplateId = tplId };
        db.Clients.Add(client);
        var project = new Project { ClientId = client.Id, Name = $"mpp-{s}" };
        db.Projects.Add(project);
        var cv = new ComponentVersion { ProjectId = project.Id, VersionString = "1.0.0", CommitSha = $"sha{s}" };
        db.ComponentVersions.Add(cv);
        foreach (var (mandateId, verdict) in mandates)
        {
            db.ConformanceFindings.Add(new ConformanceFinding
            {
                ComponentVersionId = cv.Id, AdrRef = "-", RuleId = mandateId, Claim = mandateId,
                Verdict = verdict, Method = ConformanceMethod.Deterministic, MandateId = mandateId,
            });
            // TFND-192: the reconciler only raises POA&Ms for Reviewed mandate rules.
            db.ConformanceRules.Add(new ConformanceRule
            {
                ProjectId = project.Id, AdrRef = "-", RuleId = mandateId,
                MandateId = mandateId, ReviewStatus = ReviewStatus.Reviewed,
            });
        }
        await db.SaveChangesAsync();
        return (project.Id, user.Id);
    }

    [SkippableFact]
    public async Task Failing_mandate_raises_a_dated_poam_idempotently()
    {
        Skip.IfNot(_fx.Available);
        var (projectId, userId) = await SeedAsync(("mfa", ConformanceVerdict.Fail));

        using (var scope = _fx.Scope())
        {
            var r = scope.ServiceProvider.GetRequiredService<MandatePoamReconciler>();
            var created = await r.ReconcileAsync(projectId, userId);
            Assert.Single(created);
            Assert.Equal("mfa", created[0].MandateId);
        }

        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            var poam = await db.PoamItems.SingleAsync(p => p.ProjectId == projectId && p.SourceRef == "mfa");
            Assert.Equal(PoamSource.OperationalMandate, poam.SourceKind);
            Assert.Equal(Domain.Values.Severity.High, poam.Severity);
            Assert.Equal(PoamStatus.Open, poam.Status);
            Assert.NotNull(poam.MandatePackVersion);
            // FedRAMP High: High severity → 30-day window.
            Assert.NotNull(poam.ScheduledCompletionDate);
            Assert.True(poam.ScheduledCompletionDate! > DateTimeOffset.UtcNow.AddDays(25)
                     && poam.ScheduledCompletionDate! < DateTimeOffset.UtcNow.AddDays(35));
        }

        // Re-run: no duplicate open POA&M.
        using (var scope = _fx.Scope())
        {
            var r = scope.ServiceProvider.GetRequiredService<MandatePoamReconciler>();
            Assert.Empty(await r.ReconcileAsync(projectId, userId));
            var db = _fx.Db(scope);
            Assert.Equal(1, await db.PoamItems.CountAsync(p => p.ProjectId == projectId && p.SourceRef == "mfa"));
        }
    }

    [SkippableFact]
    public async Task Unknown_mandate_raises_a_poam_but_pass_does_not()
    {
        Skip.IfNot(_fx.Available);
        var (projectId, userId) = await SeedAsync(
            ("encrypt-in-transit", ConformanceVerdict.Unknown),
            ("encrypt-at-rest", ConformanceVerdict.Pass));

        using (var scope = _fx.Scope())
        {
            var r = scope.ServiceProvider.GetRequiredService<MandatePoamReconciler>();
            var created = await r.ReconcileAsync(projectId, userId);
            Assert.Single(created);                         // only the Unknown one
            Assert.Equal("encrypt-in-transit", created[0].MandateId);
        }
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            Assert.True(await db.PoamItems.AnyAsync(p => p.ProjectId == projectId && p.SourceRef == "encrypt-in-transit"));
            Assert.False(await db.PoamItems.AnyAsync(p => p.ProjectId == projectId && p.SourceRef == "encrypt-at-rest"));
        }
    }

    [SkippableFact]
    public async Task Supply_chain_mandate_uses_the_supply_chain_source_kind()
    {
        Skip.IfNot(_fx.Available);
        var (projectId, userId) = await SeedAsync(("secure-software-attestation", ConformanceVerdict.Fail));

        using var scope = _fx.Scope();
        var r = scope.ServiceProvider.GetRequiredService<MandatePoamReconciler>();
        await r.ReconcileAsync(projectId, userId);
        var db = _fx.Db(scope);
        var poam = await db.PoamItems.SingleAsync(p => p.ProjectId == projectId && p.SourceRef == "secure-software-attestation");
        Assert.Equal(PoamSource.SupplyChainMandate, poam.SourceKind);
    }

    [SkippableFact]
    public async Task Draft_ruled_mandate_raises_no_poam()
    {
        Skip.IfNot(_fx.Available);
        var s = Guid.NewGuid().ToString("N")[..8];
        Guid projectId, userId;
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            var tplId = await db.PolicyTemplates.Where(t => t.Name == "FedRAMP High").Select(t => (Guid?)t.Id).FirstAsync();
            var user = new User { Login = $"md-{s}", DisplayName = "md", Email = $"md{s}@e.test", IsApproved = true };
            db.Users.Add(user);
            var client = new Client { Name = $"mdc-{s}", PolicyTemplateId = tplId };
            db.Clients.Add(client);
            var project = new Project { ClientId = client.Id, Name = $"mdp-{s}" };
            db.Projects.Add(project);
            var cv = new ComponentVersion { ProjectId = project.Id, VersionString = "1.0.0", CommitSha = $"sha{s}" };
            db.ComponentVersions.Add(cv);
            db.ConformanceFindings.Add(new ConformanceFinding
            {
                ComponentVersionId = cv.Id, AdrRef = "-", RuleId = "mfa", Claim = "mfa",
                Verdict = ConformanceVerdict.Fail, Method = ConformanceMethod.Deterministic, MandateId = "mfa",
            });
            // Rule is DRAFT — an unvetted/heuristic mandate tag must not raise a POA&M (TFND-192).
            db.ConformanceRules.Add(new ConformanceRule
            {
                ProjectId = project.Id, AdrRef = "-", RuleId = "mfa", MandateId = "mfa",
                ReviewStatus = ReviewStatus.Draft,
            });
            await db.SaveChangesAsync();
            (projectId, userId) = (project.Id, user.Id);
        }

        using (var scope = _fx.Scope())
        {
            var r = scope.ServiceProvider.GetRequiredService<MandatePoamReconciler>();
            Assert.Empty(await r.ReconcileAsync(projectId, userId));
            var db = _fx.Db(scope);
            Assert.False(await db.PoamItems.AnyAsync(p => p.ProjectId == projectId && p.SourceRef == "mfa"));
        }
    }
}
