using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Mcp;
using Tamp.Findings.Application.Risk;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Risk;
using Tamp.Findings.Domain.Values;
using Tamp.Findings.Mcp;

namespace Tamp.Findings.Integration.Tests;

/// <summary>
/// The write surface: policy reads, project creation, and gate hardening
/// (TFND-251 / TFND-250 / TFND-252).
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


    /// <summary>
    /// Turn agent policy authoring on or off for the instance (TFND-252).
    ///
    /// The setting is a singleton row shared by every test in the collection,
    /// so each test that depends on it sets it explicitly rather than assuming
    /// a default. The default being OFF is the behaviour under test in
    /// <c>harden_gate_is_closed_unless_the_instance_opted_in</c>.
    /// </summary>
    private async Task AgentPolicyAuthoringAsync(bool enabled)
    {
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var settings = await db.InstanceSettings
            .FirstOrDefaultAsync(x => x.Id == InstanceSettings.SingletonId);
        if (settings is null)
        {
            settings = new InstanceSettings { Id = InstanceSettings.SingletonId };
            db.InstanceSettings.Add(settings);
        }
        settings.AgentPolicyAuthoring = enabled;
        await db.SaveChangesAsync();
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

    // ---- harden_gate (TFND-252) --------------------------------------------

    [SkippableFact]
    public async Task harden_gate_enables_a_gate_nothing_else_sets()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        await AgentPolicyAuthoringAsync(true);
        using var scope = _fx.Scope();
        var policy = scope.ServiceProvider.GetRequiredService<AgentPolicyService>();
        var id = Agent(ScopeTarget.Project(w.ClientId, w.ProjectId), ProjectRole.Architect);

        var result = Json(await FindingsTools.HardenGateAsync(
            policy, Ctx(id), w.ProjectId, GateKeys.KevExposure));

        Assert.True(result.GetProperty("changed").GetBoolean());
        Assert.True(result.GetProperty("enabled").GetBoolean());
    }

    [SkippableFact]
    public async Task harden_gate_will_not_disable_anything()
    {
        Skip.IfNot(_fx.Available);

        // The tool only exposes hardening, so this goes at the service: an
        // agent cannot turn a gate off even by asking the layer beneath
        // directly.
        var w = await SeedAsync();
        await AgentPolicyAuthoringAsync(true);
        using var scope = _fx.Scope();
        var policy = scope.ServiceProvider.GetRequiredService<AgentPolicyService>();
        var id = Agent(ScopeTarget.Project(w.ClientId, w.ProjectId), ProjectRole.Architect);

        var result = await policy.HardenGateAsync(
            id, w.ProjectId, GateKeys.KevExposure, enabled: false, threshold: null);

        Assert.False(result.Changed);
        Assert.Contains("cannot disable a gate", result.Refusal!, StringComparison.Ordinal);
        Assert.Contains("harder to ship and never easier", result.Refusal!, StringComparison.Ordinal);
    }

    [SkippableFact]
    public async Task harden_gate_refuses_a_threshold_the_template_already_beats()
    {
        Skip.IfNot(_fx.Available);

        // The template pins highCves at 2. Asking for 10 is looser; the merge
        // would take 2 and discard the write, leaving the agent to report a
        // tightening that did not happen.
        var w = await SeedAsync();
        await AgentPolicyAuthoringAsync(true);
        using var scope = _fx.Scope();
        var policy = scope.ServiceProvider.GetRequiredService<AgentPolicyService>();
        var id = Agent(ScopeTarget.Project(w.ClientId, w.ProjectId), ProjectRole.Architect);

        var result = Json(await FindingsTools.HardenGateAsync(
            policy, Ctx(id), w.ProjectId, GateKeys.HighCves, threshold: 10));

        var error = result.GetProperty("error").GetString()!;
        Assert.Contains(w.TemplateLabel, error, StringComparison.Ordinal);
        Assert.Contains("not stricter", error, StringComparison.Ordinal);
        Assert.Contains("do not report this as a tightening", error, StringComparison.OrdinalIgnoreCase);
    }

    [SkippableFact]
    public async Task harden_gate_accepts_a_threshold_stricter_than_the_template()
    {
        Skip.IfNot(_fx.Available);

        // Hardening below an inherited value is the one policy edit this
        // surface exists to allow.
        var w = await SeedAsync();
        await AgentPolicyAuthoringAsync(true);
        using var scope = _fx.Scope();
        var policy = scope.ServiceProvider.GetRequiredService<AgentPolicyService>();
        var id = Agent(ScopeTarget.Project(w.ClientId, w.ProjectId), ProjectRole.Architect);

        var result = Json(await FindingsTools.HardenGateAsync(
            policy, Ctx(id), w.ProjectId, GateKeys.HighCves, threshold: 0));

        Assert.True(result.GetProperty("changed").GetBoolean());
        Assert.Equal(0, result.GetProperty("threshold").GetDouble());
    }

    [SkippableFact]
    public async Task harden_gate_refuses_an_unknown_gate_rather_than_storing_it()
    {
        Skip.IfNot(_fx.Available);

        // The evaluator ignores unknown keys, so a stored one is a setting that
        // looks real and does nothing.
        var w = await SeedAsync();
        await AgentPolicyAuthoringAsync(true);
        using var scope = _fx.Scope();
        var policy = scope.ServiceProvider.GetRequiredService<AgentPolicyService>();
        var id = Agent(ScopeTarget.Project(w.ClientId, w.ProjectId), ProjectRole.Architect);

        var result = Json(await FindingsTools.HardenGateAsync(
            policy, Ctx(id), w.ProjectId, "noSuchGate"));

        Assert.Contains("not a gate this instance knows", result.GetProperty("error").GetString(), StringComparison.Ordinal);
    }

    [SkippableFact]
    public async Task harden_gate_refuses_a_project_outside_scope()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        await AgentPolicyAuthoringAsync(true);
        using var scope = _fx.Scope();
        var policy = scope.ServiceProvider.GetRequiredService<AgentPolicyService>();
        var id = Agent(ScopeTarget.Project(w.ClientId, w.ProjectId), ProjectRole.Architect);

        var result = Json(await FindingsTools.HardenGateAsync(
            policy, Ctx(id), w.ForeignProjectId, GateKeys.KevExposure));

        Assert.Contains("outside this token", result.GetProperty("error").GetString(), StringComparison.Ordinal);
    }

    [SkippableFact]
    public async Task harden_gate_is_closed_while_the_deployment_pins_enforcement()
    {
        Skip.IfNot(_fx.Available);

        // Scott's rule, and the direction matters: LOCKED CLOSES EDITING. The
        // service is built with a locked InstanceEnforcementPolicy here because
        // that is config-sourced and not something a test can set in the
        // database.
        var w = await SeedAsync();
        // Opted IN, so the refusal under test is the lock and not the setting.
        await AgentPolicyAuthoringAsync(true);
        using var scope = _fx.Scope();

        var locked = new AgentPolicyService(
            _fx.Db(scope),
            scope.ServiceProvider.GetRequiredService<AgentScope>(),
            scope.ServiceProvider.GetRequiredService<Tamp.Findings.Application.Policy.GateService>(),
            scope.ServiceProvider.GetRequiredService<Tamp.Findings.Application.Policy.PolicyResolver>(),
            new InstanceEnforcementPolicy(configLocked: true, EnforcementMode.Enforcing),
            scope.ServiceProvider.GetRequiredService<Tamp.Findings.Application.Projects.ProjectSettingsService>());

        var result = await locked.HardenGateAsync(
            Agent(ScopeTarget.Project(w.ClientId, w.ProjectId), ProjectRole.Architect),
            w.ProjectId, GateKeys.KevExposure, enabled: true, threshold: null);

        Assert.False(result.Changed);
        Assert.Contains("pins enforcement by configuration", result.Refusal!, StringComparison.Ordinal);
        Assert.Contains("not something to work around", result.Refusal!, StringComparison.Ordinal);
    }

[SkippableFact]
    public async Task harden_gate_is_closed_unless_the_instance_opted_in()
    {
        Skip.IfNot(_fx.Available);

        // The default, and the whole point of the setting: some deployments
        // want an agent that helps configure the thing, others want policy to
        // be a human act. Off is the cautious default and must actually refuse.
        var w = await SeedAsync();
        await AgentPolicyAuthoringAsync(false);
        using var scope = _fx.Scope();
        var policy = scope.ServiceProvider.GetRequiredService<AgentPolicyService>();
        var id = Agent(ScopeTarget.Project(w.ClientId, w.ProjectId), ProjectRole.Architect);

        var result = await policy.HardenGateAsync(
            id, w.ProjectId, GateKeys.KevExposure, enabled: true, threshold: null);

        Assert.False(result.Changed);
        Assert.Contains("does not let agents author policy", result.Refusal!, StringComparison.Ordinal);
        // Says where to turn it on, and says why it is off — an agent that
        // reports only "denied" sends somebody hunting.
        Assert.Contains("Instance settings", result.Refusal!, StringComparison.Ordinal);
    }

    [SkippableFact]
    public async Task harden_gate_needs_HardenGates_which_an_auditor_token_lacks()
    {
        Skip.IfNot(_fx.Available);

        // Opted in is not the same as anyone may. The capability still decides,
        // and HardenGates is Admin, InfoSec and Architect — so a read-only
        // Auditor token is refused even on an instance that allows authoring.
        var w = await SeedAsync();
        await AgentPolicyAuthoringAsync(true);
        using var scope = _fx.Scope();
        var policy = scope.ServiceProvider.GetRequiredService<AgentPolicyService>();
        var id = Agent(ScopeTarget.Project(w.ClientId, w.ProjectId), ProjectRole.Auditor);

        var result = await policy.HardenGateAsync(
            id, w.ProjectId, GateKeys.KevExposure, enabled: true, threshold: null);

        Assert.False(result.Changed);
        Assert.Contains("HardenGates", result.Refusal!, StringComparison.Ordinal);
    }

    [SkippableFact]
    public async Task hardening_never_moves_a_verdict_in_the_permissive_direction()
    {
        Skip.IfNot(_fx.Available);

        // ADR 0019 §5 as amended (TFND-253), asserted rather than asserted-in-
        // prose: after an agent write the resolved gate set must be equal or
        // stricter. Checked on the merged layer, which is what the evaluator
        // consumes.
        var w = await SeedAsync();
        await AgentPolicyAuthoringAsync(true);
        using var scope = _fx.Scope();
        var resolver = scope.ServiceProvider.GetRequiredService<Tamp.Findings.Application.Policy.PolicyResolver>();
        var policy = scope.ServiceProvider.GetRequiredService<AgentPolicyService>();
        var id = Agent(ScopeTarget.Project(w.ClientId, w.ProjectId), ProjectRole.Architect);

        var before = await resolver.ForProjectAsync(w.ProjectId);

        await policy.HardenGateAsync(id, w.ProjectId, GateKeys.KevExposure, true, null);
        await policy.HardenGateAsync(id, w.ProjectId, GateKeys.HighCves, true, 1);

        var after = await resolver.ForProjectAsync(w.ProjectId);

        foreach (var (key, was) in before.Gates)
        {
            after.Gates.TryGetValue(key, out var now);
            Assert.NotNull(now);

            // A gate that was on may not have been turned off.
            Assert.True(!was.Enabled || now!.Enabled, $"{key} was disabled by an agent write");

            // A threshold that existed may not have risen.
            if (was.Threshold is { } old && now!.Threshold is { } fresh)
                Assert.True(fresh <= old, $"{key} threshold rose from {old} to {fresh}");
        }
    }
}
