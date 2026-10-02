using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Risk;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Integration.Tests;

// TFND-208: one resolution chain for the scoring policy — project → client → the client's
// compliance template's link → default — shared by the score, the API views and the fork.
[Collection(DatabaseCollection.Name)]
public class ScoringPolicyResolverIntegrationTests
{
    private readonly DatabaseFixture _fx;
    public ScoringPolicyResolverIntegrationTests(DatabaseFixture fx) => _fx = fx;

    private sealed record World(Guid ClientId, Guid ProjectId, Guid TemplatePolicyId, Guid ProjectPolicyId);

    private async Task<World> SeedAsync()
    {
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var s = Guid.NewGuid().ToString("N")[..8];
        var templatePolicy = new RiskPolicy { Name = $"tpl-policy-{s}", Config = new RiskPolicyConfig() };
        var projectPolicy = new RiskPolicy { Name = $"prj-policy-{s}", Config = new RiskPolicyConfig() };
        var template = new PolicyTemplate { Name = $"tpl-{s}", RiskPolicyId = templatePolicy.Id };
        var client = new Client { Name = $"sp-client-{s}", PolicyTemplateId = template.Id };
        var project = new Project { ClientId = client.Id, Name = $"sp-project-{s}" };
        db.RiskPolicies.AddRange(templatePolicy, projectPolicy);
        db.PolicyTemplates.Add(template);
        db.Clients.Add(client);
        db.Projects.Add(project);
        await db.SaveChangesAsync();
        return new World(client.Id, project.Id, templatePolicy.Id, projectPolicy.Id);
    }

    [SkippableFact]
    public async Task A_project_with_no_override_scores_against_its_clients_template_policy()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        using var scope = _fx.Scope();
        var r = scope.ServiceProvider.GetRequiredService<ScoringPolicyResolver>();

        Assert.Equal(w.TemplatePolicyId, (await r.ResolveRowAsync(null, w.ProjectId))!.Id);
        Assert.Equal(w.TemplatePolicyId, (await r.ResolveRowAsync(w.ClientId, null))!.Id);   // client-level aggregates
        Assert.Equal(w.TemplatePolicyId, (await r.ForProjectAsync(w.ProjectId)).Id);
    }

    [SkippableFact]
    public async Task A_project_override_beats_the_template()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            db.Projects.Single(p => p.Id == w.ProjectId).RiskPolicyId = w.ProjectPolicyId;
            await db.SaveChangesAsync();
        }
        using var scope2 = _fx.Scope();
        var r = scope2.ServiceProvider.GetRequiredService<ScoringPolicyResolver>();

        Assert.Equal(w.ProjectPolicyId, (await r.ResolveRowAsync(null, w.ProjectId))!.Id);
    }
}
