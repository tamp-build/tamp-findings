using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Policy;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Risk;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Integration.Tests;

// The compose model (TFND-203): the project's findings-assigned archetype is an ADDITIVE layer
// over the client baseline. These prove the layer actually reaches the effective policy through
// the resolver, and that an unclassified project fails upward to Service.
[Collection(DatabaseCollection.Name)]
public class ArchetypeComposeIntegrationTests
{
    private readonly DatabaseFixture _fx;
    public ArchetypeComposeIntegrationTests(DatabaseFixture fx) => _fx = fx;

    private async Task<Guid> SeedProjectAsync(ProjectArchetype? archetype)
    {
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var s = Guid.NewGuid().ToString("N")[..8];
        var client = new Client { Name = $"arc-{s}" };   // no baseline template — isolate the archetype layer
        db.Clients.Add(client);
        var project = new Project { ClientId = client.Id, Name = $"arcp-{s}", Archetype = archetype };
        db.Projects.Add(project);
        await db.SaveChangesAsync();
        return project.Id;
    }

    [SkippableFact]
    public async Task Service_archetype_adds_dast_iac_and_base_image_to_the_effective_policy()
    {
        Skip.IfNot(_fx.Available);
        var projectId = await SeedProjectAsync(ProjectArchetype.ServiceApp);

        using var scope = _fx.Scope();
        var resolver = scope.ServiceProvider.GetRequiredService<PolicyResolver>();
        var eff = await resolver.EffectiveGatesAsync(projectId, null);

        Assert.True(eff.Gates[GateKeys.CriticalDast].Enabled);
        Assert.True(eff.Gates[GateKeys.CriticalIac].Enabled);
        Assert.True(eff.Gates[GateKeys.BaseImageAge].Enabled);
    }

    [SkippableFact]
    public async Task Library_archetype_adds_no_web_image_or_iac_gate()
    {
        Skip.IfNot(_fx.Available);
        var projectId = await SeedProjectAsync(ProjectArchetype.Library);

        using var scope = _fx.Scope();
        var resolver = scope.ServiceProvider.GetRequiredService<PolicyResolver>();
        var eff = await resolver.EffectiveGatesAsync(projectId, null);

        Assert.False(eff.Gates.ContainsKey(GateKeys.CriticalDast));
        Assert.False(eff.Gates.ContainsKey(GateKeys.CriticalIac));
        Assert.False(eff.Gates.ContainsKey(GateKeys.BaseImageAge));
    }

    [SkippableFact]
    public async Task Unclassified_project_fails_upward_to_service_obligations()
    {
        Skip.IfNot(_fx.Available);
        var projectId = await SeedProjectAsync(null);   // never classified

        using var scope = _fx.Scope();
        var resolver = scope.ServiceProvider.GetRequiredService<PolicyResolver>();
        var eff = await resolver.EffectiveGatesAsync(projectId, null);

        // Same obligations as an explicit Service — the strictest posture, by omission.
        Assert.True(eff.Gates[GateKeys.CriticalDast].Enabled);
        Assert.True(eff.Gates[GateKeys.CriticalIac].Enabled);
    }
}
