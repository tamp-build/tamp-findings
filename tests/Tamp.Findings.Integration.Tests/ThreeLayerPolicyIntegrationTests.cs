using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Policy;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Risk;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Integration.Tests;

// The three-layer policy resolution (ADR 0007). GateDecisionService now judges a
// build against the MERGED gate set, so these prove the two properties the
// wiring depends on: a project with no template resolves to exactly its own
// gates (behaviour-preserving), and a template gate is inherited down.
[Collection(DatabaseCollection.Name)]
public class ThreeLayerPolicyIntegrationTests
{
    private readonly DatabaseFixture _fx;

    public ThreeLayerPolicyIntegrationTests(DatabaseFixture fx) => _fx = fx;

    [SkippableFact]
    public async Task A_project_with_no_template_resolves_to_its_own_gates()
    {
        Skip.IfNot(_fx.Available);

        var suffix = Guid.NewGuid().ToString("N")[..8];
        Guid projectId;
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            var client = new Client { Name = $"tl-client-{suffix}" };
            var project = new Project
            {
                ClientId = client.Id,
                Name = $"tl-project-{suffix}",
                GatesConfig = new ProjectGatesConfig
                {
                    Gates = { [GateKeys.CriticalSast] = new GateConfig { Enabled = true, Threshold = 0 } },
                },
            };
            db.Clients.Add(client);
            db.Projects.Add(project);
            await db.SaveChangesAsync();
            projectId = project.Id;
        }

        using var s = _fx.Scope();
        var resolver = s.ServiceProvider.GetRequiredService<PolicyResolver>();
        var eff = await resolver.ForProjectAsync(projectId);

        // Exactly the project's own gate, attributed to the project — nothing
        // inherited, because there is no template or client layer.
        Assert.True(eff.Gates[GateKeys.CriticalSast].Enabled);
        Assert.Equal("this project", eff.Gates[GateKeys.CriticalSast].Source);
        Assert.DoesNotContain(GateKeys.KevExposure, eff.Gates.Keys);
    }

    [SkippableFact]
    public async Task A_template_gate_is_inherited_and_the_project_adds_its_own()
    {
        Skip.IfNot(_fx.Available);

        var suffix = Guid.NewGuid().ToString("N")[..8];
        Guid projectId;
        string templateLabel;
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);

            var template = new PolicyTemplate
            {
                Name = $"tl-template-{suffix}",
                Version = 3,
                Layer = new PolicyLayer
                {
                    Mode = EnforcementMode.Enforcing,
                    Gates = { [GateKeys.KevExposure] = new GateConfig { Enabled = true, Threshold = 0 } },
                },
            };
            db.PolicyTemplates.Add(template);
            await db.SaveChangesAsync();
            templateLabel = template.Label;

            var client = new Client { Name = $"tl-client-{suffix}", PolicyTemplateId = template.Id };
            var project = new Project
            {
                ClientId = client.Id,
                Name = $"tl-project-{suffix}",
                GatesConfig = new ProjectGatesConfig
                {
                    Gates = { [GateKeys.CriticalSast] = new GateConfig { Enabled = true, Threshold = 0 } },
                },
            };
            db.Clients.Add(client);
            db.Projects.Add(project);
            await db.SaveChangesAsync();
            projectId = project.Id;
        }

        using var s = _fx.Scope();
        var resolver = s.ServiceProvider.GetRequiredService<PolicyResolver>();
        var eff = await resolver.ForProjectAsync(projectId);

        // The template's KEV gate is inherited (attributed to the template) and
        // the project's own critical-SAST gate stands beside it.
        Assert.True(eff.Gates[GateKeys.KevExposure].Enabled);
        Assert.Equal(templateLabel, eff.Gates[GateKeys.KevExposure].Source);
        Assert.True(eff.Gates[GateKeys.CriticalSast].Enabled);
        Assert.Equal("this project", eff.Gates[GateKeys.CriticalSast].Source);
        // Enforcing mode flows down from the template.
        Assert.Equal(EnforcementMode.Enforcing, eff.Mode!.Value);
        Assert.Equal(templateLabel, eff.Mode.Source);
    }
}
