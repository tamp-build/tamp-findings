using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Projects;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Integration.Tests;

// Classifying a project's archetype is the trust boundary (TFND-203): it is set on the findings
// side by a human with EditGates, never by the ingesting caller. These pin that gate and the
// read-back.
[Collection(DatabaseCollection.Name)]
public class ArchetypeSettingIntegrationTests
{
    private readonly DatabaseFixture _fx;
    public ArchetypeSettingIntegrationTests(DatabaseFixture fx) => _fx = fx;

    [SkippableFact]
    public async Task Only_edit_gates_can_classify_and_it_reads_back()
    {
        Skip.IfNot(_fx.Available);
        var s = Guid.NewGuid().ToString("N")[..8];
        Guid projectId, clientId, userId; string login;
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            var user = new User { Login = $"ar-{s}", DisplayName = "ar", Email = $"ar{s}@e.test", IsApproved = true };
            db.Users.Add(user);
            var client = new Client { Name = $"arc-{s}" };
            db.Clients.Add(client);
            var project = new Project { ClientId = client.Id, Name = $"arp-{s}" };
            db.Projects.Add(project);
            await db.SaveChangesAsync();
            (projectId, clientId, userId, login) = (project.Id, client.Id, user.Id, user.Login);
        }

        var target = ScopeTarget.Project(clientId, projectId);

        // A Viewer cannot classify (EditGates is Admin + InfoSec).
        using (var scope = _fx.Scope())
        {
            var svc = scope.ServiceProvider.GetRequiredService<ProjectSettingsService>();
            var viewer = Principal.For(userId, login, isAdmin: false, []);
            var denied = await svc.SaveArchetypeAsync(viewer, target, projectId, ProjectArchetype.ServiceApp);
            Assert.False(denied.Success);
            Assert.True(denied.WasDenied);
        }

        // InfoSec classifies it as a Service, and it reads back.
        using (var scope = _fx.Scope())
        {
            var svc = scope.ServiceProvider.GetRequiredService<ProjectSettingsService>();
            var infosec = Principal.For(userId, login, isAdmin: false, [ProjectRole.InfoSecOfficer]);
            Assert.True((await svc.SaveArchetypeAsync(infosec, target, projectId, ProjectArchetype.ServiceApp)).Success);
            Assert.Equal(ProjectArchetype.ServiceApp, await svc.ArchetypeAsync(projectId));

            // Clearing it (unclassified → fail-upward) is also a classify action.
            Assert.True((await svc.SaveArchetypeAsync(infosec, target, projectId, null)).Success);
            Assert.Null(await svc.ArchetypeAsync(projectId));
        }
    }
}
