using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Domain.Risk;
using Tamp.Findings.Domain.Values;
using static Tamp.Findings.Integration.Tests.ApiAHarness;

namespace Tamp.Findings.Integration.Tests;

// /risk-policies, policy assignment, /projects/{id}/policy-and-gates, fork, gates, control-dispositions
[Collection(DatabaseCollection.Name)]
public class ApiARiskPolicyTests
{
    private readonly DatabaseFixture _fx;
    public ApiARiskPolicyTests(DatabaseFixture fx) => _fx = fx;

    private async Task<(HttpClient Admin, Guid AdminId, HttpClient Plain, HttpClient Unapproved, HttpClient Anon)> ClientsAsync()
    {
        var adminId = await UserAsync(_fx, admin: true);
        var plain = await UserAsync(_fx, admin: false);
        var unapproved = await UserAsync(_fx, admin: false, approved: false);
        return (Http(_fx, adminId), adminId, Http(_fx, plain), Http(_fx, unapproved), Http(_fx, null));
    }

    // An approved user with a read-only grant on the client: sees the project, lacks every write capability.
    private async Task<HttpClient> ViewerAsync(Guid clientId)
    {
        var id = await UserAsync(_fx, admin: false);
        await GrantAsync(_fx, id, ProjectRole.Auditor, clientId, null);
        return Http(_fx, id);
    }

    private async Task<JsonElement> DefaultPolicyAsync(HttpClient http)
    {
        var list = await GetJsonAsync(http, "/risk-policies");
        var def = list.EnumerateArray().First(p => p.GetProperty("isDefault").GetBoolean());
        return await GetJsonAsync(http, $"/risk-policies/{def.GetProperty("id").GetGuid()}");
    }

    private static async Task<JsonElement> BodyAsync(HttpResponseMessage r) =>
        (await JsonAsync(r)).RootElement.Clone();

    // ---------------------------------------------------------------- read

    [SkippableFact]
    public async Task List_puts_the_default_first_and_get_returns_the_full_config()
    {
        Skip.IfNot(_fx.Available);
        var c = await ClientsAsync();

        var list = await GetJsonAsync(c.Plain, "/risk-policies");
        var rows = list.EnumerateArray().ToList();
        Assert.True(rows.Count >= 2);
        Assert.True(rows[0].GetProperty("isDefault").GetBoolean());
        Assert.Single(rows, r => r.GetProperty("isDefault").GetBoolean());

        var full = await GetJsonAsync(c.Plain, $"/risk-policies/{rows[0].GetProperty("id").GetGuid()}");
        Assert.Equal(rows[0].GetProperty("name").GetString(), full.GetProperty("name").GetString());
        Assert.True(full.GetProperty("config").GetProperty("schemaVersion").GetInt32() >= 1);
        Assert.True(full.GetProperty("config").GetProperty("categories").EnumerateObject().Any());

        Assert.Equal(HttpStatusCode.NotFound, (await c.Plain.GetAsync($"/risk-policies/{Guid.NewGuid()}")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await c.Anon.GetAsync("/risk-policies")).StatusCode);
    }

    // ---------------------------------------------------------------- create / clone / update / delete

    [SkippableFact]
    public async Task Create_validates_authorizes_and_rejects_duplicate_names()
    {
        Skip.IfNot(_fx.Available);
        var c = await ClientsAsync();
        var config = (await DefaultPolicyAsync(c.Admin)).GetProperty("config");
        var name = $"apia-create-{Sfx()}";

        Assert.Equal(HttpStatusCode.Forbidden, (await c.Plain.PostAsJsonAsync("/risk-policies", new { name, description = "d", config })).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await c.Unapproved.PostAsJsonAsync("/risk-policies", new { name, description = "d", config })).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await c.Anon.PostAsJsonAsync("/risk-policies", new { name, description = "d", config })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await c.Admin.PostAsJsonAsync("/risk-policies", new { name = "  ", description = "d", config })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await c.Admin.PostAsJsonAsync("/risk-policies", new { name, description = "d", config = new { schemaVersion = 0 } })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await c.Admin.PostAsJsonAsync("/risk-policies", new { name, description = "d", config = (object?)null })).StatusCode);

        var ok = await c.Admin.PostAsJsonAsync("/risk-policies", new { name = $" {name} ", description = "made by test", config });
        Assert.Equal(HttpStatusCode.Created, ok.StatusCode);
        var created = await BodyAsync(ok);
        Assert.Equal(name, created.GetProperty("name").GetString());   // trimmed
        Assert.False(created.GetProperty("isDefault").GetBoolean());
        Assert.False(created.GetProperty("isSeeded").GetBoolean());

        var dup = await c.Admin.PostAsJsonAsync("/risk-policies", new { name, description = "again", config });
        Assert.Equal(HttpStatusCode.Conflict, dup.StatusCode);
    }

    [SkippableFact]
    public async Task Clone_copies_the_config_under_a_new_name()
    {
        Skip.IfNot(_fx.Available);
        var c = await ClientsAsync();
        var def = await DefaultPolicyAsync(c.Admin);
        var id = def.GetProperty("id").GetGuid();
        var name = $"apia-clone-{Sfx()}";

        Assert.Equal(HttpStatusCode.Forbidden, (await c.Plain.PostAsJsonAsync($"/risk-policies/{id}/clone", new { name })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await c.Admin.PostAsJsonAsync($"/risk-policies/{id}/clone", new { name = "" })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await c.Admin.PostAsJsonAsync($"/risk-policies/{Guid.NewGuid()}/clone", new { name })).StatusCode);

        var ok = await c.Admin.PostAsJsonAsync($"/risk-policies/{id}/clone", new { name });
        Assert.Equal(HttpStatusCode.Created, ok.StatusCode);
        var clone = await BodyAsync(ok);
        Assert.NotEqual(id, clone.GetProperty("id").GetGuid());
        Assert.False(clone.GetProperty("isDefault").GetBoolean());
        Assert.Equal(def.GetProperty("config").GetProperty("schemaVersion").GetInt32(),
            clone.GetProperty("config").GetProperty("schemaVersion").GetInt32());

        Assert.Equal(HttpStatusCode.Conflict, (await c.Admin.PostAsJsonAsync($"/risk-policies/{id}/clone", new { name })).StatusCode);
    }

    [SkippableFact]
    public async Task Update_edits_in_place_and_validates()
    {
        Skip.IfNot(_fx.Available);
        var c = await ClientsAsync();
        var config = (await DefaultPolicyAsync(c.Admin)).GetProperty("config");
        var s = Sfx();
        var a = await BodyAsync(await c.Admin.PostAsJsonAsync("/risk-policies", new { name = $"apia-upd-a-{s}", description = "orig", config }));
        var b = await BodyAsync(await c.Admin.PostAsJsonAsync("/risk-policies", new { name = $"apia-upd-b-{s}", description = "orig", config }));
        var idA = a.GetProperty("id").GetGuid();

        Assert.Equal(HttpStatusCode.Forbidden, (await c.Plain.PatchAsJsonAsync($"/risk-policies/{idA}", new { name = "x" })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await c.Admin.PatchAsJsonAsync($"/risk-policies/{Guid.NewGuid()}", new { name = "x" })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await c.Admin.PatchAsJsonAsync($"/risk-policies/{idA}", new { config = new { schemaVersion = 0 } })).StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, (await c.Admin.PatchAsJsonAsync($"/risk-policies/{idA}", new { name = b.GetProperty("name").GetString() })).StatusCode);

        var newName = $"apia-upd-renamed-{s}";
        var ok = await c.Admin.PatchAsJsonAsync($"/risk-policies/{idA}", new { name = $" {newName} ", description = "changed", config });
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        var updated = await BodyAsync(ok);
        Assert.Equal(newName, updated.GetProperty("name").GetString());
        Assert.Equal("changed", updated.GetProperty("description").GetString());

        // blank description clears it; blank name is ignored
        var cleared = await BodyAsync(await c.Admin.PatchAsJsonAsync($"/risk-policies/{idA}", new { name = " ", description = "  " }));
        Assert.Equal(newName, cleared.GetProperty("name").GetString());
        Assert.Equal(JsonValueKind.Null, cleared.GetProperty("description").ValueKind);
    }

    [SkippableFact]
    public async Task Delete_removes_a_policy_but_never_the_default()
    {
        Skip.IfNot(_fx.Available);
        var c = await ClientsAsync();
        var def = await DefaultPolicyAsync(c.Admin);
        var made = await BodyAsync(await c.Admin.PostAsJsonAsync("/risk-policies",
            new { name = $"apia-del-{Sfx()}", description = "x", config = def.GetProperty("config") }));
        var id = made.GetProperty("id").GetGuid();

        Assert.Equal(HttpStatusCode.Forbidden, (await c.Plain.DeleteAsync($"/risk-policies/{id}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await c.Admin.DeleteAsync($"/risk-policies/{Guid.NewGuid()}")).StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, (await c.Admin.DeleteAsync($"/risk-policies/{def.GetProperty("id").GetGuid()}")).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await c.Admin.DeleteAsync($"/risk-policies/{id}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await c.Plain.GetAsync($"/risk-policies/{id}")).StatusCode);
    }

    [SkippableFact]
    public async Task Set_default_moves_the_flag_atomically()
    {
        Skip.IfNot(_fx.Available);
        var c = await ClientsAsync();
        var def = await DefaultPolicyAsync(c.Admin);
        var originalId = def.GetProperty("id").GetGuid();
        var made = await BodyAsync(await c.Admin.PostAsJsonAsync("/risk-policies",
            new { name = $"apia-default-{Sfx()}", description = "x", config = def.GetProperty("config") }));
        var newId = made.GetProperty("id").GetGuid();

        try
        {
            Assert.Equal(HttpStatusCode.Forbidden, (await c.Plain.PostAsync($"/risk-policies/{newId}/set-default", null)).StatusCode);
            Assert.Equal(HttpStatusCode.NotFound, (await c.Admin.PostAsync($"/risk-policies/{Guid.NewGuid()}/set-default", null)).StatusCode);
            Assert.Equal(HttpStatusCode.NoContent, (await c.Admin.PostAsync($"/risk-policies/{newId}/set-default", null)).StatusCode);

            var list = await GetJsonAsync(c.Admin, "/risk-policies");
            var defaults = list.EnumerateArray().Where(p => p.GetProperty("isDefault").GetBoolean()).ToList();
            Assert.Equal(newId, Assert.Single(defaults).GetProperty("id").GetGuid());
        }
        finally
        {
            // leave the shared instance with its original default
            await c.Admin.PostAsync($"/risk-policies/{originalId}/set-default", null);
        }
        var after = await GetJsonAsync(c.Admin, "/risk-policies");
        Assert.Equal(originalId, after.EnumerateArray().Single(p => p.GetProperty("isDefault").GetBoolean()).GetProperty("id").GetGuid());
    }

    // ---------------------------------------------------------------- assignment

    [SkippableFact]
    public async Task Policy_can_be_assigned_to_and_cleared_from_clients_and_projects()
    {
        Skip.IfNot(_fx.Available);
        var c = await ClientsAsync();
        var tree = await ClientProjectAsync(_fx);
        var def = await DefaultPolicyAsync(c.Admin);
        var made = await BodyAsync(await c.Admin.PostAsJsonAsync("/risk-policies",
            new { name = $"apia-assign-{Sfx()}", description = "x", config = def.GetProperty("config") }));
        var pid = made.GetProperty("id").GetGuid();

        // client
        Assert.Equal(HttpStatusCode.Forbidden, (await (await ViewerAsync(tree.ClientId)).PatchAsJsonAsync($"/clients/{tree.ClientId}/policy", new { policyId = pid })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await c.Admin.PatchAsJsonAsync($"/clients/{Guid.NewGuid()}/policy", new { policyId = pid })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await c.Admin.PatchAsJsonAsync($"/clients/{tree.ClientId}/policy", new { policyId = Guid.NewGuid() })).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await c.Admin.PatchAsJsonAsync($"/clients/{tree.ClientId}/policy", new { policyId = pid })).StatusCode);
        var clients = await GetJsonAsync(c.Admin, "/clients");
        Assert.Equal(pid, clients.EnumerateArray().Single(x => x.GetProperty("id").GetGuid() == tree.ClientId).GetProperty("riskPolicyId").GetGuid());
        Assert.Equal(HttpStatusCode.NoContent, (await c.Admin.PatchAsJsonAsync($"/clients/{tree.ClientId}/policy", new { policyId = (Guid?)null })).StatusCode);

        // project
        Assert.Equal(HttpStatusCode.Forbidden, (await (await ViewerAsync(tree.ClientId)).PatchAsJsonAsync($"/projects/{tree.ProjectId}/policy", new { policyId = pid })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await c.Admin.PatchAsJsonAsync($"/projects/{Guid.NewGuid()}/policy", new { policyId = pid })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await c.Admin.PatchAsJsonAsync($"/projects/{tree.ProjectId}/policy", new { policyId = Guid.NewGuid() })).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await c.Admin.PatchAsJsonAsync($"/projects/{tree.ProjectId}/policy", new { policyId = pid })).StatusCode);

        var view = await GetJsonAsync(c.Admin, $"/projects/{tree.ProjectId}/policy-and-gates");
        Assert.Equal(pid, view.GetProperty("assignedPolicyId").GetGuid());
        Assert.Equal(pid, view.GetProperty("effectivePolicyId").GetGuid());
        Assert.True(view.GetProperty("effectiveFromProject").GetBoolean());

        Assert.Equal(HttpStatusCode.NoContent, (await c.Admin.PatchAsJsonAsync($"/projects/{tree.ProjectId}/policy", new { policyId = (Guid?)null })).StatusCode);
        var inherited = await GetJsonAsync(c.Admin, $"/projects/{tree.ProjectId}/policy-and-gates");
        Assert.Equal(JsonValueKind.Null, inherited.GetProperty("assignedPolicyId").ValueKind);
        Assert.False(inherited.GetProperty("effectiveFromProject").GetBoolean());
        Assert.Empty(inherited.GetProperty("gates").GetProperty("gates").EnumerateObject());
    }

    [SkippableFact]
    public async Task Policy_and_gates_view_reports_where_the_effective_policy_came_from()
    {
        Skip.IfNot(_fx.Available);
        var c = await ClientsAsync();
        var tree = await ClientProjectAsync(_fx);
        var def = await DefaultPolicyAsync(c.Admin);
        var made = await BodyAsync(await c.Admin.PostAsJsonAsync("/risk-policies",
            new { name = $"apia-clientpol-{Sfx()}", description = "x", config = def.GetProperty("config") }));
        var pid = made.GetProperty("id").GetGuid();
        await c.Admin.PatchAsJsonAsync($"/clients/{tree.ClientId}/policy", new { policyId = pid });

        var view = await GetJsonAsync((await ViewerAsync(tree.ClientId)), $"/projects/{tree.ProjectId}/policy-and-gates");

        Assert.Equal(pid, view.GetProperty("effectivePolicyId").GetGuid());
        Assert.True(view.GetProperty("effectiveFromClient").GetBoolean());
        Assert.False(view.GetProperty("effectiveFromProject").GetBoolean());
        Assert.Equal(HttpStatusCode.NotFound, (await (await ViewerAsync(tree.ClientId)).GetAsync($"/projects/{Guid.NewGuid()}/policy-and-gates")).StatusCode);
    }

    [SkippableFact]
    public async Task Fork_clones_the_effective_policy_onto_the_project()
    {
        Skip.IfNot(_fx.Available);
        var c = await ClientsAsync();
        var tree = await ClientProjectAsync(_fx);

        Assert.Equal(HttpStatusCode.Forbidden, (await (await ViewerAsync(tree.ClientId)).PostAsync($"/projects/{tree.ProjectId}/policy/fork", null)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await c.Admin.PostAsync($"/projects/{Guid.NewGuid()}/policy/fork", null)).StatusCode);

        var first = await c.Admin.PostAsync($"/projects/{tree.ProjectId}/policy/fork", null);
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        var fork = await BodyAsync(first);
        Assert.Contains("custom", fork.GetProperty("name").GetString());
        Assert.Contains(tree.ProjectName, fork.GetProperty("name").GetString());

        var view = await GetJsonAsync(c.Admin, $"/projects/{tree.ProjectId}/policy-and-gates");
        Assert.Equal(fork.GetProperty("id").GetGuid(), view.GetProperty("assignedPolicyId").GetGuid());

        // Forking again must not collide on the unique name.
        var second = await c.Admin.PostAsync($"/projects/{tree.ProjectId}/policy/fork", null);
        Assert.Equal(HttpStatusCode.OK, second.StatusCode);
        Assert.NotEqual(fork.GetProperty("id").GetGuid(), (await BodyAsync(second)).GetProperty("id").GetGuid());
    }

    // ---------------------------------------------------------------- gates

    [SkippableFact]
    public async Task Gates_are_saved_through_the_capability_gated_service()
    {
        Skip.IfNot(_fx.Available);
        var c = await ClientsAsync();
        var tree = await ClientProjectAsync(_fx);
        var url = $"/projects/{tree.ProjectId}/gates";
        object Gates(params (string Key, bool Enabled, double? Threshold)[] g) => new
        {
            gates = new
            {
                schemaVersion = 1,
                gates = g.ToDictionary(x => x.Key, x => new { enabled = x.Enabled, threshold = x.Threshold }),
                enforcementMode = (string?)null,
            },
        };

        Assert.Equal(HttpStatusCode.BadRequest, (await c.Admin.PatchAsJsonAsync(url, new { gates = new { schemaVersion = 0 } })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound,
            (await c.Admin.PatchAsJsonAsync($"/projects/{Guid.NewGuid()}/gates", Gates((GateKeys.AnyCves, true, null)))).StatusCode);
        // Not approved yet: the visibility boundary answers first, with a 404.
        Assert.Equal(HttpStatusCode.NotFound,
            (await c.Unapproved.PatchAsJsonAsync(url, Gates((GateKeys.AnyCves, true, null)))).StatusCode);
        // An approved user with no role at the project lacks EditGates.
        Assert.Equal(HttpStatusCode.Forbidden,
            (await (await ViewerAsync(tree.ClientId)).PatchAsJsonAsync(url, Gates((GateKeys.AnyCves, true, null)))).StatusCode);
        // Negative thresholds are refused.
        Assert.Equal(HttpStatusCode.BadRequest,
            (await c.Admin.PatchAsJsonAsync(url, Gates((GateKeys.CriticalCves, true, -1)))).StatusCode);

        var ok = await c.Admin.PatchAsJsonAsync(url, Gates((GateKeys.CriticalCves, true, 0), (GateKeys.CoverageFloor, true, 70), (GateKeys.AnyCves, false, null)));
        Assert.Equal(HttpStatusCode.NoContent, ok.StatusCode);

        var view = await GetJsonAsync(c.Admin, $"/projects/{tree.ProjectId}/policy-and-gates");
        var gates = view.GetProperty("gates").GetProperty("gates");
        Assert.True(gates.GetProperty(GateKeys.CriticalCves).GetProperty("enabled").GetBoolean());
        Assert.Equal(70, gates.GetProperty(GateKeys.CoverageFloor).GetProperty("threshold").GetDouble());

        // Saving the same thing again is a no-op that still succeeds.
        Assert.Equal(HttpStatusCode.NoContent,
            (await c.Admin.PatchAsJsonAsync(url, Gates((GateKeys.CriticalCves, true, 0), (GateKeys.CoverageFloor, true, 70)))).StatusCode);

        // A project-scoped InfoSec officer may edit gates.
        var infosec = await UserAsync(_fx, admin: false);
        await GrantAsync(_fx, infosec, ProjectRole.InfoSecOfficer, null, tree.ProjectId);
        Assert.Equal(HttpStatusCode.NoContent,
            (await Http(_fx, infosec).PatchAsJsonAsync(url, Gates((GateKeys.CriticalCves, false, null)))).StatusCode);
    }

    // ---------------------------------------------------------------- control dispositions

    [SkippableFact]
    public async Task Control_dispositions_validate_and_persist_project_layer_assertions()
    {
        Skip.IfNot(_fx.Available);
        var c = await ClientsAsync();
        var tree = await ClientProjectAsync(_fx);
        var url = $"/projects/{tree.ProjectId}/control-dispositions";
        object Body(params object[] d) => new { dispositions = d };

        Assert.Equal(HttpStatusCode.Forbidden, (await (await ViewerAsync(tree.ClientId)).PatchAsJsonAsync(url, Body(new { controlIds = new[] { "SC-13" }, kind = "Gated" }))).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await c.Admin.PatchAsJsonAsync($"/projects/{Guid.NewGuid()}/control-dispositions",
            Body(new { controlIds = new[] { "SC-13" }, kind = "Gated" }))).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await c.Admin.PatchAsJsonAsync(url, Body())).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await c.Admin.PatchAsJsonAsync(url, new { dispositions = (object?)null })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await c.Admin.PatchAsJsonAsync(url, Body(new { controlIds = new[] { "SC-13" }, kind = "Owned" }))).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await c.Admin.PatchAsJsonAsync(url, Body(new { controlIds = Array.Empty<string>(), kind = "Gated" }))).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await c.Admin.PatchAsJsonAsync(url, Body(new { controlIds = new[] { "SC-13" }, kind = "NotApplicable" }))).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await c.Admin.PatchAsJsonAsync(url, Body(new { controlIds = new[] { "SC-13" }, kind = "Inherited", justification = "platform" }))).StatusCode);

        var ok = await c.Admin.PatchAsJsonAsync(url, Body(
            new { controlIds = new[] { "SC-13", " ", "SC-28" }, kind = "Gated", gates = new[] { GateKeys.CriticalCves } },
            new { controlIds = new[] { "AC-2" }, kind = "NotApplicable", justification = "  no accounts  " },
            new { controlIds = new[] { "AU-2" }, kind = "inherited", justification = "platform audit", inheritedFrom = " aws " }));
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        var result = await BodyAsync(ok);
        Assert.Equal(0, result.GetProperty("inScope").GetInt32());   // no framework assigned to the client

        // Re-asserting a control replaces its prior claim rather than duplicating it.
        Assert.Equal(HttpStatusCode.OK, (await c.Admin.PatchAsJsonAsync(url, Body(
            new { controlIds = new[] { "SC-13" }, kind = "NotApplicable", justification = "now N/A" }))).StatusCode);

        using var scope = _fx.Scope();
        var project = await _fx.Db(scope).Projects.AsNoTracking().SingleAsync(p => p.Id == tree.ProjectId);
        var assertions = project.PolicyLayer!.Assertions;
        Assert.Equal(4, assertions.Count);
        var sc13 = Assert.Single(assertions, a => a.ControlIds.Contains("SC-13"));
        Assert.Equal(ControlDispositionKind.NotApplicable, sc13.Kind);
        Assert.Equal("now N/A", sc13.Justification);
        var au2 = Assert.Single(assertions, a => a.ControlIds.Contains("AU-2"));
        Assert.Equal("aws", au2.InheritedFrom);
        Assert.Equal("platform audit", au2.Justification);
        Assert.Equal("no accounts", Assert.Single(assertions, a => a.ControlIds.Contains("AC-2")).Justification);
    }
}
