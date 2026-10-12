using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Mcp;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Risk;
using Tamp.Findings.Domain.Values;
using Tamp.Findings.Mcp;

namespace Tamp.Findings.Integration.Tests;

/// <summary>
/// The write surface: policy reads and project creation (TFND-251 / TFND-250).
///
/// Gate hardening (TFND-252) is not here: no mintable agent role holds
/// EditGates, so the tool is parked rather than shipped dead. Its
/// implementation and tests live on tfnd/252-harden-gate-parked.
///
/// The refusals are the feature. Everything an agent is told it cannot do here
/// has a plausible-looking way to do it anyway — loosen through the project
/// layer, create inside another client, tighten a gate a template already pins —
/// and each of those would produce a confident false report rather than a
/// visible failure. So most of these assert that the refusal happens AND that
/// it says why.
/// </summary>
[Collection(DatabaseCollection.Name)]
public class ApiBMcpWriteSurfaceTests
{
    private readonly DatabaseFixture _fx;
    public ApiBMcpWriteSurfaceTests(DatabaseFixture fx) => _fx = fx;

    private sealed record World(
        Guid ClientId, Guid ProjectId, Guid ForeignProjectId, string TemplateLabel);

    /// <summary>
    /// A client carrying a compliance template that pins one gate, and a project
    /// under it. The template is the point: it is what makes "your write would
    /// be discarded by the merge" reachable.
    /// </summary>
    private async Task<World> SeedAsync()
    {
        var s = ApiBSupport.Suffix();
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);

        // Label is computed as "{Name} v{Version}", so the provenance string the
        // merge reports is derived rather than chosen here.
        var template = new PolicyTemplate
        {
            Name = $"apib-tpl-{s}",
            Layer = new PolicyLayer
            {
                Gates = { [GateKeys.HighCves] = new GateConfig { Enabled = true, Threshold = 2 } },
            },
        };
        db.PolicyTemplates.Add(template);

        var client = new Client { Name = $"apib-w-{s}", PolicyTemplateId = template.Id };
        var otherClient = new Client { Name = $"apib-w-o-{s}" };
        db.Clients.AddRange(client, otherClient);

        var project = new Project { ClientId = client.Id, Name = $"p-{s}" };
        var foreign = new Project { ClientId = otherClient.Id, Name = $"f-{s}" };
        db.Projects.AddRange(project, foreign);

        await db.SaveChangesAsync();
        return new World(client.Id, project.Id, foreign.Id, template.Label);
    }

    private static AgentIdentity Agent(ScopeTarget scope, ProjectRole? role = null) =>
        new(Guid.NewGuid(), "agent",
            Principal.For(Guid.Empty, "agent:test", isAdmin: false, role is { } r ? [r] : []),
            scope);

    private static JsonElement Json(object o) =>
        JsonSerializer.SerializeToElement(o, new JsonSerializerOptions(JsonSerializerDefaults.Web));

    private static AgentContext Ctx(AgentIdentity id)
    {
        var ctx = new AgentContext();
        ctx.Attach(id);
        return ctx;
    }

    // ---- get_policy (TFND-251) ---------------------------------------------

    [SkippableFact]
    public async Task get_policy_names_the_layer_that_imposed_each_gate()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        using var scope = _fx.Scope();
        var reads = scope.ServiceProvider.GetRequiredService<AgentReadService>();

        var policy = Json(await FindingsTools.GetPolicyAsync(
            reads, Ctx(Agent(ScopeTarget.Project(w.ClientId, w.ProjectId))), w.ProjectId));

        var pinned = policy.GetProperty("gates").EnumerateArray()
            .First(g => g.GetProperty("key").GetString() == GateKeys.HighCves);

        Assert.True(pinned.GetProperty("enabled").GetBoolean());
        Assert.Equal(2, pinned.GetProperty("threshold").GetDouble());
        // Provenance: the template's label, not "this project".
        Assert.Equal(w.TemplateLabel, pinned.GetProperty("source").GetString());
        // The project itself says nothing about this gate.
        Assert.Equal(JsonValueKind.Null, pinned.GetProperty("projectEnabled").ValueKind);
    }

    [SkippableFact]
    public async Task get_policy_reports_every_known_gate_including_the_ungated_ones()
    {
        Skip.IfNot(_fx.Available);

        // "Not gated here" and "passes" lead to opposite advice, so an agent
        // must be able to tell them apart.
        var w = await SeedAsync();
        using var scope = _fx.Scope();
        var reads = scope.ServiceProvider.GetRequiredService<AgentReadService>();

        var policy = Json(await FindingsTools.GetPolicyAsync(
            reads, Ctx(Agent(ScopeTarget.Project(w.ClientId, w.ProjectId))), w.ProjectId));

        var keys = policy.GetProperty("gates").EnumerateArray()
            .Select(g => g.GetProperty("key").GetString()).ToArray();

        Assert.Equal(GateEvaluator.WellKnownGateKeys.Length, keys.Length);
        Assert.Contains(policy.GetProperty("gates").EnumerateArray(),
            g => !g.GetProperty("enabled").GetBoolean());
    }

    [SkippableFact]
    public async Task get_policy_works_regardless_of_the_enforcement_lock()
    {
        Skip.IfNot(_fx.Available);

        // Scott's rule: reads are unconditional. An agent that cannot read the
        // policy cannot explain a verdict it is already allowed to see.
        var w = await SeedAsync();
        using var scope = _fx.Scope();
        var reads = scope.ServiceProvider.GetRequiredService<AgentReadService>();

        var policy = Json(await FindingsTools.GetPolicyAsync(
            reads, Ctx(Agent(ScopeTarget.Project(w.ClientId, w.ProjectId))), w.ProjectId));

        Assert.True(policy.TryGetProperty("gates", out _));
        Assert.True(policy.GetProperty("enforcement").TryGetProperty("locked", out _));
    }

    [SkippableFact]
    public async Task get_policy_refuses_a_project_outside_scope()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        using var scope = _fx.Scope();
        var reads = scope.ServiceProvider.GetRequiredService<AgentReadService>();

        var policy = Json(await FindingsTools.GetPolicyAsync(
            reads, Ctx(Agent(ScopeTarget.Project(w.ClientId, w.ProjectId))), w.ForeignProjectId));

        Assert.Contains("outside this token", policy.GetProperty("error").GetString(), StringComparison.Ordinal);
    }

    // ---- create_project (TFND-250) -----------------------------------------

    [SkippableFact]
    public async Task create_project_puts_it_in_the_tokens_own_client()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        using var scope = _fx.Scope();
        var admin = scope.ServiceProvider.GetRequiredService<AgentAdminService>();
        var reads = scope.ServiceProvider.GetRequiredService<AgentReadService>();
        var id = Agent(ScopeTarget.Client(w.ClientId), ProjectRole.Architect);

        var created = Json(await FindingsTools.CreateProjectAsync(
            admin, Ctx(id), $"made-by-agent-{ApiBSupport.Suffix()}", "from a test"));

        var projectId = created.GetProperty("projectId").GetGuid();
        Assert.NotEqual(Guid.Empty, projectId);
        Assert.Contains("no way to delete", created.GetProperty("note").GetString(), StringComparison.Ordinal);

        // It landed inside the token's client, which is the only place it could.
        var tree = Json(await FindingsTools.ListScopeAsync(reads, Ctx(Agent(ScopeTarget.Client(w.ClientId)))));
        Assert.Contains(tree.GetProperty("projects").EnumerateArray(),
            p => p.GetProperty("projectId").GetGuid() == projectId);
    }

    [SkippableFact]
    public async Task create_project_is_refused_without_the_architect_role()
    {
        Skip.IfNot(_fx.Available);

        // CreateProject is held by Admin and Architect, and an agent is never
        // Admin — so an Auditor token cannot create anything.
        var w = await SeedAsync();
        using var scope = _fx.Scope();
        var admin = scope.ServiceProvider.GetRequiredService<AgentAdminService>();

        var refused = Json(await FindingsTools.CreateProjectAsync(
            admin, Ctx(Agent(ScopeTarget.Client(w.ClientId), ProjectRole.Auditor)), "nope"));

        Assert.Contains("Architect", refused.GetProperty("error").GetString(), StringComparison.Ordinal);
    }

    [SkippableFact]
    public async Task create_project_refuses_a_duplicate_name_in_the_same_client()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        using var scope = _fx.Scope();
        var admin = scope.ServiceProvider.GetRequiredService<AgentAdminService>();
        var id = Agent(ScopeTarget.Client(w.ClientId), ProjectRole.Architect);
        var name = $"dup-{ApiBSupport.Suffix()}";

        Assert.True(Json(await FindingsTools.CreateProjectAsync(admin, Ctx(id), name))
            .TryGetProperty("projectId", out _));

        var second = Json(await FindingsTools.CreateProjectAsync(
            admin, Ctx(Agent(ScopeTarget.Client(w.ClientId), ProjectRole.Architect)), name));

        Assert.Contains("already has a project", second.GetProperty("error").GetString(), StringComparison.Ordinal);
    }

}
