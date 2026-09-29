using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Zt;
using Tamp.Findings.Domain.Compliance;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Integration.Tests;

// tamp-ztt findings-side (TFND-188 / ADR 0010). Verifies the shipped seeds, the
// ruleset-serve (/zt-profile query), and the derive-on-read score end to end against a
// real DB, on the conservative-by-construction guarantees.
[Collection(DatabaseCollection.Name)]
public class ZtIntegrationTests
{
    private readonly DatabaseFixture _fx;
    public ZtIntegrationTests(DatabaseFixture fx) => _fx = fx;

    [SkippableFact]
    public void Ztmm_model_and_mandate_pack_seed_on_startup()
    {
        Skip.IfNot(_fx.Available);
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);

        var model = db.MaturityModelCatalogs.Single(m => m.IsCurrent);
        Assert.Equal(5, model.Pillars.Count); // the 5 ZTMM pillars
        Assert.Contains(model.Pillars, p => p.Name == "Identity");
        Assert.All(model.Pillars, p => Assert.Contains(p.Functions, f => f.CrossCutting)); // cross-cutting folded in

        var pack = db.MandatePacks.Single(p => p.IsCurrent);
        Assert.Contains(pack.Mandates, m => m.MandateId == "mfa" && m.Tool == MandateTool.Ztt);
        Assert.Contains(pack.Mandates, m => m.MandateId == "secure-software-attestation" && m.Tool == MandateTool.Findings);
    }

    [SkippableFact]
    public async Task Zt_profile_serves_the_model_and_only_ztt_mandates_with_in_force_status()
    {
        Skip.IfNot(_fx.Available);
        var s = Guid.NewGuid().ToString("N")[..8];
        Guid projectId;

        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            var modelId = await db.MaturityModelCatalogs.Where(m => m.IsCurrent).Select(m => m.Id).FirstAsync();
            var client = new Client { Name = $"zt-{s}", MaturityModelId = modelId };
            db.Clients.Add(client);
            var project = new Project { ClientId = client.Id, Name = $"ztp-{s}" };
            db.Projects.Add(project);
            await db.SaveChangesAsync();
            projectId = project.Id;
        }

        using (var scope = _fx.Scope())
        {
            var q = scope.ServiceProvider.GetRequiredService<ZtProfileQuery>();
            var profile = await q.ForProjectAsync(projectId);

            Assert.NotNull(profile);
            Assert.Equal(5, profile!.Model.Pillars.Count);
            // Serves ONLY ztt's operational lane (supply-chain stays with findings).
            Assert.All(profile.Mandates, m => Assert.Contains(m.Id, new[] { "mfa", "encrypt-at-rest", "encrypt-in-transit", "ipv6", "logging-maturity" }));
            // MFA's directive (M-22-09-mfa) is active in the seeded corpus → in force.
            Assert.True(profile.Mandates.Single(m => m.Id == "mfa").InForce);
        }
    }

    [SkippableFact]
    public async Task System_with_no_client_maturity_model_has_no_zt_profile()
    {
        Skip.IfNot(_fx.Available);
        var s = Guid.NewGuid().ToString("N")[..8];
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var client = new Client { Name = $"nom-{s}" }; // no MaturityModelId
        db.Clients.Add(client);
        var project = new Project { ClientId = client.Id, Name = $"nomp-{s}" };
        db.Projects.Add(project);
        await db.SaveChangesAsync();

        var q = scope.ServiceProvider.GetRequiredService<ZtProfileQuery>();
        Assert.Null(await q.ForProjectAsync(project.Id));
    }

    // TFND-199: the dashboard entry point resolves the project's repo-backed ZtSystem and scores it.
    [SkippableFact]
    public async Task ForProject_resolves_the_linked_system_and_scores_it()
    {
        Skip.IfNot(_fx.Available);
        var s = Guid.NewGuid().ToString("N")[..8];
        Guid projectId; var sysName = $"sys-{s}";

        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            var modelId = await db.MaturityModelCatalogs.Where(m => m.IsCurrent).Select(m => m.Id).FirstAsync();
            var client = new Client { Name = $"fpc-{s}", MaturityModelId = modelId };
            db.Clients.Add(client);
            var project = new Project { ClientId = client.Id, Name = $"fpp-{s}" };
            db.Projects.Add(project);
            var cv = new ComponentVersion { ProjectId = project.Id, VersionString = "1.0.0", CommitSha = $"fp{s}" };
            db.ComponentVersions.Add(cv);
            db.ConformanceFindings.Add(new ConformanceFinding
            {
                ComponentVersionId = cv.Id, AdrRef = "ADR 1", RuleId = "auth", Claim = "auth",
                Verdict = ConformanceVerdict.Pass, Method = ConformanceMethod.Deterministic,
                ZtPillar = "Identity", ZtFunction = "Authentication", ZtStage = 3,
            });
            db.ZtSystems.Add(new ZtSystem { ClientId = client.Id, ProjectId = project.Id, Name = sysName, SystemKind = "app" });
            await db.SaveChangesAsync();
            projectId = project.Id;
        }

        using (var scope = _fx.Scope())
        {
            var q = scope.ServiceProvider.GetRequiredService<ZtScoreQuery>();
            var cov = await q.ForProjectAsync(projectId);
            Assert.NotNull(cov);
            Assert.Equal(sysName, cov!.SystemName);
            Assert.Equal("app", cov.SystemKind);
            Assert.NotNull(cov.Coverage.SystemScore);
            var auth = cov.Coverage.Functions.Single(f => f.Pillar == "Identity" && f.Function == "Authentication");
            Assert.Equal(ZtDisposition.OwnedVerified, auth.Disposition);
        }
    }

    [SkippableFact]
    public async Task ForProject_is_null_when_no_system_is_linked()
    {
        Skip.IfNot(_fx.Available);
        var s = Guid.NewGuid().ToString("N")[..8];
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var modelId = await db.MaturityModelCatalogs.Where(m => m.IsCurrent).Select(m => m.Id).FirstAsync();
        var client = new Client { Name = $"nsc-{s}", MaturityModelId = modelId };
        db.Clients.Add(client);
        var project = new Project { ClientId = client.Id, Name = $"nsp-{s}" };  // no ZtSystem
        db.Projects.Add(project);
        await db.SaveChangesAsync();

        var q = scope.ServiceProvider.GetRequiredService<ZtScoreQuery>();
        Assert.Null(await q.ForProjectAsync(project.Id));
    }

    [SkippableFact]
    public async Task Score_derives_owned_evidence_honours_na_and_caps_inheritance()
    {
        Skip.IfNot(_fx.Available);
        var s = Guid.NewGuid().ToString("N")[..8];
        Guid systemId;

        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            var modelId = await db.MaturityModelCatalogs.Where(m => m.IsCurrent).Select(m => m.Id).FirstAsync();
            var user = new User { Login = $"ztu-{s}", DisplayName = "z", Email = $"z{s}@e.test", IsApproved = true };
            db.Users.Add(user);
            var client = new Client { Name = $"zc-{s}", MaturityModelId = modelId };
            db.Clients.Add(client);
            var project = new Project { ClientId = client.Id, Name = $"zp-{s}" };
            db.Projects.Add(project);
            var cv = new ComponentVersion { ProjectId = project.Id, VersionString = "1.0.0", CommitSha = $"sha{s}" };
            db.ComponentVersions.Add(cv);

            // Owned maturity evidence: ztt posted a verified stage-3 Authentication.
            db.ConformanceFindings.Add(new ConformanceFinding
            {
                ComponentVersionId = cv.Id, AdrRef = "ADR 1", RuleId = "auth", Claim = "auth",
                Verdict = ConformanceVerdict.Pass, Method = ConformanceMethod.Deterministic,
                ZtPillar = "Identity", ZtFunction = "Authentication", ZtStage = 3,
            });

            var offering = new EnterpriseOffering { ClientId = client.Id, ServiceLevelId = $"splunk-{s}", Name = "Splunk",
                FunctionScores = [ new() { Pillar = "Identity", Function = "Visibility & Analytics", Stage = 3 } ] };
            db.EnterpriseOfferings.Add(offering);

            var system = new ZtSystem { ClientId = client.Id, ProjectId = project.Id, Name = $"sys-{s}" };
            db.ZtSystems.Add(system);
            await db.SaveChangesAsync();
            systemId = system.Id;

            // An attested inheritance edge for V&A, and an N/A pick for a Data function.
            db.ZtInheritanceEdges.Add(new ZtInheritanceEdge
            {
                SystemId = system.Id, OfferingId = offering.Id, Pillar = "Identity", Function = "Visibility & Analytics",
                Statement = "Splunk team confirmed onboarding", AttesterLogin = user.Login,
                AttestedAt = DateTimeOffset.UtcNow, ExpiresAt = DateTimeOffset.UtcNow.AddDays(365), AuthorUserId = user.Id,
            });
            db.ZtSystemPicks.Add(new ZtSystemPick
            {
                SystemId = system.Id, Pillar = "Data", Function = "Data Encryption",
                Kind = ZtPickKind.NotApplicable, Justification = "no data at rest", AuthorUserId = user.Id,
            });
            await db.SaveChangesAsync();
        }

        using (var scope = _fx.Scope())
        {
            var q = scope.ServiceProvider.GetRequiredService<ZtScoreQuery>();
            var cov = await q.ForSystemAsync(systemId);
            Assert.NotNull(cov);

            var auth = cov!.Functions.Single(f => f.Pillar == "Identity" && f.Function == "Authentication");
            Assert.Equal(ZtDisposition.OwnedVerified, auth.Disposition);
            Assert.Equal(3, auth.Stage);

            var va = cov.Functions.Single(f => f.Pillar == "Identity" && f.Function == "Visibility & Analytics");
            Assert.Equal(ZtDisposition.InheritedAttested, va.Disposition);
            Assert.Equal(3, va.Stage); // capped at the provider

            var enc = cov.Functions.Single(f => f.Pillar == "Data" && f.Function == "Data Encryption");
            Assert.Equal(ZtDisposition.NotApplicable, enc.Disposition);
            Assert.False(enc.InDenominator);

            // Everything else floors at 1; system score is a real gauge, never null here.
            Assert.NotNull(cov.SystemScore);
            Assert.True(cov.SystemScore >= 1.0);
        }
    }
}
