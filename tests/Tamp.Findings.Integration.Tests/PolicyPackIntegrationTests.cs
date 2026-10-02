using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Policy;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Risk;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Integration.Tests;

// The distributable policy content pack (TFND-203 phase B): baselines are DB rows updated by an
// admin applying a versioned pack, so a baseline change ships as a DB update, not an app republish.
[Collection(DatabaseCollection.Name)]
public class PolicyPackIntegrationTests
{
    private readonly DatabaseFixture _fx;
    public PolicyPackIntegrationTests(DatabaseFixture fx) => _fx = fx;

    private static GateConfig On(double? t = null) => new() { Enabled = true, Threshold = t };

    [SkippableFact]
    public async Task Applying_a_pack_upserts_baselines_idempotently_and_survives_the_seeder()
    {
        Skip.IfNot(_fx.Available);
        var s = Guid.NewGuid().ToString("N")[..8];
        var name = $"Pack Baseline {s}";
        Guid userId; string login;
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            var user = new User { Login = $"pp-{s}", DisplayName = "pp", Email = $"pp{s}@e.test", IsApproved = true };
            db.Users.Add(user);
            await db.SaveChangesAsync();
            (userId, login) = (user.Id, user.Login);
        }

        var admin = Principal.For(userId, login, isAdmin: true, []);
        var pack = new PolicyPack
        {
            PackVersion = "test-1",
            Templates =
            [
                new PolicyPackTemplate
                {
                    Name = name, Scoring = "default",
                    Layer = new PolicyLayer { Mode = EnforcementMode.Enforcing, Gates = { [GateKeys.KevExposure] = On(0) } },
                },
            ],
        };

        // First apply: created, not seeded, version 1.
        using (var scope = _fx.Scope())
        {
            var r = await scope.ServiceProvider.GetRequiredService<PolicyPackService>().ApplyAsync(admin, pack);
            Assert.True(r.Success);
            Assert.Equal(1, r.Value!.Created);
        }
        using (var scope = _fx.Scope())
        {
            var tpl = await _fx.Db(scope).PolicyTemplates.SingleAsync(t => t.Name == name);
            Assert.False(tpl.IsSeeded);   // pack-managed, so the code seeder leaves it alone
            Assert.Equal(1, tpl.Version);
            Assert.True(tpl.Layer.Gates[GateKeys.KevExposure].Enabled);
        }

        // Re-apply the SAME pack: idempotent — nothing changes, no version churn.
        using (var scope = _fx.Scope())
        {
            var r = await scope.ServiceProvider.GetRequiredService<PolicyPackService>().ApplyAsync(admin, pack);
            Assert.Equal(0, r.Value!.Created + r.Value.Updated);
            Assert.Equal(1, r.Value.Unchanged);
        }

        // Change the layer: updated, version bumped.
        pack.Templates[0].Layer.Gates[GateKeys.SbomAge] = On(14);
        using (var scope = _fx.Scope())
        {
            var r = await scope.ServiceProvider.GetRequiredService<PolicyPackService>().ApplyAsync(admin, pack);
            Assert.Equal(1, r.Value!.Updated);
        }
        using (var scope = _fx.Scope())
        {
            var tpl = await _fx.Db(scope).PolicyTemplates.SingleAsync(t => t.Name == name);
            Assert.Equal(2, tpl.Version);
            Assert.True(tpl.Layer.Gates[GateKeys.SbomAge].Enabled);
        }

        // A non-privileged principal cannot apply a pack.
        using (var scope = _fx.Scope())
        {
            var viewer = Principal.For(userId, login, isAdmin: false, []);
            var denied = await scope.ServiceProvider.GetRequiredService<PolicyPackService>().ApplyAsync(viewer, pack);
            Assert.False(denied.Success);
            Assert.True(denied.WasDenied);
        }
    }

    [SkippableFact]
    public async Task An_applied_archetype_layer_overrides_the_in_code_bootstrap_for_projects_of_that_archetype()
    {
        Skip.IfNot(_fx.Available);
        var s = Guid.NewGuid().ToString("N")[..8];
        Guid userId, projectId; string login;
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            var user = new User { Login = $"pa-{s}", DisplayName = "pa", Email = $"pa{s}@e.test", IsApproved = true };
            var client = new Client { Name = $"pa-client-{s}" };
            var project = new Project { ClientId = client.Id, Name = $"pa-project-{s}", Archetype = ProjectArchetype.Library };
            db.Users.Add(user); db.Clients.Add(client); db.Projects.Add(project);
            await db.SaveChangesAsync();
            (userId, login, projectId) = (user.Id, user.Login, project.Id);
        }
        var admin = Principal.For(userId, login, isAdmin: true, []);

        try
        {
            using (var scope = _fx.Scope())
            {
                var before = await scope.ServiceProvider.GetRequiredService<PolicyResolver>().ForProjectAsync(projectId);
                Assert.False(before.Gates.TryGetValue(GateKeys.KevExposure, out var g0) && g0.Enabled);
            }

            var pack = new PolicyPack
            {
                PackVersion = "arch-1",
                Archetypes = [new PolicyPackArchetype { Archetype = "library", Layer = new PolicyLayer { Gates = { [GateKeys.KevExposure] = On(0) } } }],
            };
            using (var scope = _fx.Scope())
            {
                var r = await scope.ServiceProvider.GetRequiredService<PolicyPackService>().ApplyAsync(admin, pack);
                Assert.True(r.Success);
                Assert.Equal(1, r.Value!.Created);
                var bad = await scope.ServiceProvider.GetRequiredService<PolicyPackService>().ApplyAsync(admin,
                    new PolicyPack { Archetypes = [new PolicyPackArchetype { Archetype = "nope", Layer = new PolicyLayer() }] });
                Assert.False(bad.Success);
            }
            using (var scope = _fx.Scope())
            {
                var after = await scope.ServiceProvider.GetRequiredService<PolicyResolver>().ForProjectAsync(projectId);
                Assert.True(after.Gates[GateKeys.KevExposure].Enabled);
            }
        }
        finally
        {
            // Global state: other tests rely on the in-code Library layer.
            using var scope = _fx.Scope();
            var db = _fx.Db(scope);
            db.ArchetypeDefinitions.RemoveRange(db.ArchetypeDefinitions);
            await db.SaveChangesAsync();
        }
    }
}
