using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;
using static Tamp.Findings.Integration.Tests.ApiAHarness;

namespace Tamp.Findings.Integration.Tests;

// /projects/{id}/vex-statements (list/create/ingest-cdx) and /vex-statements/{id} (patch/delete)
[Collection(DatabaseCollection.Name)]
public class ApiAVexTests
{
    private readonly DatabaseFixture _fx;
    public ApiAVexTests(DatabaseFixture fx) => _fx = fx;

    private sealed record World(Tree Tree, HttpClient Admin, HttpClient Auditor, HttpClient LeadDev, HttpClient InfoSec);

    private async Task<World> SeedAsync()
    {
        var tree = await ClientProjectAsync(_fx);
        var admin = await UserAsync(_fx, admin: true);
        async Task<HttpClient> Member(ProjectRole role)
        {
            var id = await UserAsync(_fx, admin: false);
            await GrantAsync(_fx, id, role, tree.ClientId, null);
            return Http(_fx, id);
        }
        return new World(tree, Http(_fx, admin), await Member(ProjectRole.Auditor), await Member(ProjectRole.LeadDev), await Member(ProjectRole.InfoSecOfficer));
    }

    private static async Task<JsonElement> BodyAsync(HttpResponseMessage r) => (await JsonAsync(r)).RootElement.Clone();

    private static object Draft(string advisory, string purl = "pkg:nuget/Foo", string status = "UnderInvestigation",
        string? justification = null, string? version = null, string? impact = null, string? url = null) =>
        new { purl, componentVersion = version, advisoryId = advisory, status, justification, impactStatement = impact, responseReferenceUrl = url };

    private static StringContent Json(string s) => new(s, Encoding.UTF8, "application/json");

    // ---------------------------------------------------------------- create / list

    [SkippableFact]
    public async Task Create_and_list_statements_with_retired_filter()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        var url = $"/projects/{w.Tree.ProjectId}/vex-statements";
        var s = Sfx();

        var draft = await w.Admin.PostAsJsonAsync(url, Draft($"CVE-A-{s}", impact: "  looking  ", url: "https://example.test/x"));
        Assert.Equal(HttpStatusCode.Created, draft.StatusCode);
        var d = await BodyAsync(draft);
        Assert.Equal("UnderInvestigation", d.GetProperty("status").GetString());
        Assert.Equal("looking", d.GetProperty("impactStatement").GetString());
        Assert.Equal(w.Tree.ProjectId, d.GetProperty("projectId").GetGuid());
        Assert.Equal(JsonValueKind.Null, d.GetProperty("retiredAt").ValueKind);

        var suppress = await BodyAsync(await w.Admin.PostAsJsonAsync(url,
            Draft($"CVE-B-{s}", "pkg:npm/bar", "NotAffected", "VulnerableCodeNotPresent", version: "1.2.3")));
        Assert.Equal("1.2.3", suppress.GetProperty("componentVersion").GetString());
        Assert.Equal("VulnerableCodeNotPresent", suppress.GetProperty("justification").GetString());
        var fixedOne = await w.InfoSec.PostAsJsonAsync(url, Draft($"CVE-C-{s}", "pkg:nuget/Baz", "Fixed"));
        Assert.Equal(HttpStatusCode.Created, fixedOne.StatusCode);

        var list = await GetJsonAsync(w.Admin, url);
        Assert.Equal(3, list.GetArrayLength());
        // most recently updated first
        Assert.Equal($"CVE-C-{s}", list[0].GetProperty("advisoryId").GetString());

        var retire = await w.Admin.DeleteAsync($"/vex-statements/{suppress.GetProperty("id").GetGuid()}");
        Assert.Equal(HttpStatusCode.NoContent, retire.StatusCode);
        Assert.Equal(2, (await GetJsonAsync(w.Admin, url)).GetArrayLength());
        var withRetired = await GetJsonAsync(w.Admin, url + "?includeRetired=true");
        Assert.Equal(3, withRetired.GetArrayLength());
        Assert.Contains(withRetired.EnumerateArray(), x => x.GetProperty("retiredAt").ValueKind != JsonValueKind.Null);

        Assert.Equal(HttpStatusCode.Unauthorized, (await Http(_fx, null).GetAsync(url)).StatusCode);
    }

    [SkippableFact]
    public async Task Create_enforces_validation_capabilities_and_uniqueness()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        var url = $"/projects/{w.Tree.ProjectId}/vex-statements";
        var s = Sfx();

        Assert.Equal(HttpStatusCode.BadRequest, (await w.Admin.PostAsJsonAsync(url, Draft(""))).StatusCode);                          // advisory
        Assert.Equal(HttpStatusCode.BadRequest, (await w.Admin.PostAsJsonAsync(url, Draft($"CVE-{s}", ""))).StatusCode);              // purl
        Assert.Equal(HttpStatusCode.BadRequest, (await w.Admin.PostAsJsonAsync(url, Draft($"CVE-{s}", "nuget/Foo"))).StatusCode);     // not a purl
        Assert.Equal(HttpStatusCode.BadRequest, (await w.Admin.PostAsJsonAsync(url, Draft($"CVE-{s}", status: "NotAffected"))).StatusCode);   // needs justification
        Assert.Equal(HttpStatusCode.BadRequest, (await w.Admin.PostAsJsonAsync(url, Draft($"CVE-{s}", status: "NotAffected", justification: "None"))).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await w.Admin.PostAsJsonAsync(url, Draft($"CVE-{s}", url: "not a url"))).StatusCode);

        // Read-only role cannot author at all; unknown project is a 404; anonymous 401.
        Assert.Equal(HttpStatusCode.Forbidden, (await w.Auditor.PostAsJsonAsync(url, Draft($"CVE-{s}"))).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await w.Admin.PostAsJsonAsync($"/projects/{Guid.NewGuid()}/vex-statements", Draft($"CVE-{s}"))).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Http(_fx, null).PostAsJsonAsync(url, Draft($"CVE-{s}"))).StatusCode);

        // Lead Dev drafts, InfoSec publishes: a suppressing status needs PublishVex.
        Assert.Equal(HttpStatusCode.Created, (await w.LeadDev.PostAsJsonAsync(url, Draft($"CVE-L-{s}"))).StatusCode);
        var lead = await w.LeadDev.PostAsJsonAsync(url, Draft($"CVE-S-{s}", "pkg:nuget/Sup", "Fixed"));
        Assert.Equal(HttpStatusCode.Forbidden, lead.StatusCode);

        // An active statement already covers the same advisory + component.
        Assert.Equal(HttpStatusCode.BadRequest, (await w.Admin.PostAsJsonAsync(url, Draft($"CVE-L-{s}"))).StatusCode);
    }

    // ---------------------------------------------------------------- update / retire

    [SkippableFact]
    public async Task Update_changes_status_in_place_and_refuses_retired_statements()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        var url = $"/projects/{w.Tree.ProjectId}/vex-statements";
        var s = Sfx();
        var created = await BodyAsync(await w.Admin.PostAsJsonAsync(url, Draft($"CVE-U-{s}", impact: "orig")));
        var id = created.GetProperty("id").GetGuid();

        var up = await w.Admin.PatchAsJsonAsync($"/vex-statements/{id}",
            new { status = "NotAffected", justification = "ComponentNotPresent", impactStatement = (string?)null, responseReferenceUrl = "https://example.test/r" });
        Assert.Equal(HttpStatusCode.OK, up.StatusCode);
        var updated = await BodyAsync(up);
        Assert.Equal("NotAffected", updated.GetProperty("status").GetString());
        Assert.Equal("orig", updated.GetProperty("impactStatement").GetString());           // null keeps the stored value
        Assert.Equal("https://example.test/r", updated.GetProperty("responseReferenceUrl").GetString());
        Assert.Equal($"CVE-U-{s}", updated.GetProperty("advisoryId").GetString());          // identity untouched
        Assert.Equal(created.GetProperty("createdAt").GetDateTimeOffset(), updated.GetProperty("createdAt").GetDateTimeOffset());

        // moving into a suppressing status needs PublishVex
        var other = await BodyAsync(await w.LeadDev.PostAsJsonAsync(url, Draft($"CVE-U2-{s}", "pkg:nuget/Two")));
        Assert.Equal(HttpStatusCode.Forbidden,
            (await w.LeadDev.PatchAsJsonAsync($"/vex-statements/{other.GetProperty("id").GetGuid()}", new { status = "Fixed" })).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden,
            (await w.Auditor.PatchAsJsonAsync($"/vex-statements/{id}", new { impactStatement = "x" })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest,
            (await w.Admin.PatchAsJsonAsync($"/vex-statements/{id}", new { responseReferenceUrl = "garbage" })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await w.Admin.PatchAsJsonAsync($"/vex-statements/{Guid.NewGuid()}", new { status = "Fixed" })).StatusCode);

        Assert.Equal(HttpStatusCode.NoContent, (await w.Admin.DeleteAsync($"/vex-statements/{id}")).StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, (await w.Admin.PatchAsJsonAsync($"/vex-statements/{id}", new { status = "Fixed" })).StatusCode);
        // retiring again is harmless
        Assert.Equal(HttpStatusCode.NoContent, (await w.Admin.DeleteAsync($"/vex-statements/{id}")).StatusCode);
    }

    [SkippableFact]
    public async Task Retire_requires_publish_capability_and_an_existing_statement()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        var url = $"/projects/{w.Tree.ProjectId}/vex-statements";
        var made = await BodyAsync(await w.Admin.PostAsJsonAsync(url, Draft($"CVE-R-{Sfx()}")));
        var id = made.GetProperty("id").GetGuid();

        Assert.Equal(HttpStatusCode.NotFound, (await w.Admin.DeleteAsync($"/vex-statements/{Guid.NewGuid()}")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await w.Auditor.DeleteAsync($"/vex-statements/{id}")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await w.LeadDev.DeleteAsync($"/vex-statements/{id}")).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await w.InfoSec.DeleteAsync($"/vex-statements/{id}")).StatusCode);
    }

    // ---------------------------------------------------------------- CycloneDX import

    [SkippableFact]
    public async Task Cyclonedx_import_maps_states_and_justifications_and_upserts()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        var url = $"/projects/{w.Tree.ProjectId}/vex-statements/ingest-cdx";
        var s = Sfx();
        var doc = $$"""
        {
          "vulnerabilities": [
            { "id": "CVE-1-{{s}}", "analysis": { "state": "in_triage" }, "affects": [ { "ref": "pkg:nuget/Alpha@1.0.0" } ] },
            { "id": "CVE-2-{{s}}", "analysis": { "state": "exploitable", "detail": "reachable" }, "affects": [ { "ref": "pkg:nuget/Beta" } ] },
            { "id": "CVE-3-{{s}}", "analysis": { "state": "not_affected", "justification": "code_not_present", "detail": "gone" }, "affects": [ { "ref": "pkg:npm/gamma@2.0.0" }, { "purl": "pkg:npm/delta@3.0.0" } ] },
            { "id": "CVE-4-{{s}}", "analysis": { "state": "false_positive", "justification": "component_not_present" }, "affects": [ { "ref": "pkg:pypi/eps" } ] },
            { "id": "CVE-5-{{s}}", "analysis": { "state": "resolved" }, "affects": [ { "ref": "pkg:pypi/zeta" } ] },
            { "id": "CVE-6-{{s}}", "analysis": { "state": "not_affected", "justification": "code_not_reachable" }, "affects": [ { "ref": "pkg:pypi/eta1" } ] },
            { "id": "CVE-7-{{s}}", "analysis": { "state": "not_affected", "justification": "protected_at_runtime" }, "affects": [ { "ref": "pkg:pypi/eta2" } ] },
            { "id": "CVE-8-{{s}}", "analysis": { "state": "not_affected", "justification": "weird_unknown" }, "affects": [ { "ref": "pkg:pypi/eta3" } ] },
            { "id": "CVE-9-{{s}}", "analysis": { "state": "under_investigation" }, "affects": [ { "ref": "pkg:pypi/theta" } ] },
            { "id": "CVE-10-{{s}}", "analysis": { "state": "resolved_with_pedigree" }, "affects": [ { "ref": "pkg:pypi/iota" } ] },
            { "id": "", "analysis": { "state": "in_triage" }, "affects": [ { "ref": "pkg:pypi/kappa" } ] },
            { "id": "CVE-11-{{s}}", "analysis": { "state": "mystery" }, "affects": [ { "ref": "pkg:pypi/lambda" } ] },
            { "id": "CVE-12-{{s}}", "affects": [ { "ref": "pkg:pypi/mu" } ] },
            { "id": "CVE-13-{{s}}", "analysis": { "state": "in_triage" } },
            { "id": "CVE-14-{{s}}", "analysis": { "state": "in_triage" }, "affects": [ { "ref": "not-a-purl" }, { "other": 1 } ] },
            { "id": "CVE-15-{{s}}", "analysis": { "state": "not_affected" }, "affects": [ { "ref": "pkg:pypi/nu" } ] },
            { "id": "CVE-16-{{s}}", "analysis": { "state": "not_affected", "justification": "protected_by_compiler" }, "affects": [ { "ref": "pkg:pypi/xi" } ] },
            { "id": "CVE-17-{{s}}", "analysis": { "state": "not_affected", "justification": "requires_configuration" }, "affects": [ { "ref": "pkg:pypi/omicron" } ] },
            { "id": "CVE-18-{{s}}", "analysis": { "state": "not_affected", "justification": "protected_by_mitigating_control" }, "affects": [ { "ref": "pkg:pypi/pi" } ] }
          ]
        }
        """;

        var first = await w.Admin.PostAsync(url, Json(doc));
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        var r = await BodyAsync(first);
        // created: 1,2,3(x2),4,5,6,7,9,10,16,17,18 ; failed: blank id + #8 + #15 ; skipped: 11,12,13,14(x2 affects)
        Assert.Equal(13, r.GetProperty("created").GetInt32());
        Assert.Equal(0, r.GetProperty("updated").GetInt32());
        Assert.Equal(3, r.GetProperty("failed").GetInt32());
        Assert.Equal(5, r.GetProperty("skipped").GetInt32());

        using (var scope = _fx.Scope())
        {
            var rows = await _fx.Db(scope).VexStatements.AsNoTracking().Where(v => v.ProjectId == w.Tree.ProjectId).ToListAsync();
            var alpha = rows.Single(v => v.AdvisoryId == $"CVE-1-{s}");
            Assert.Equal("pkg:nuget/Alpha", alpha.Purl);
            Assert.Equal("1.0.0", alpha.ComponentVersion);
            Assert.Equal(VexStatementStatus.UnderInvestigation, alpha.Status);
            Assert.Equal(VexStatementStatus.Affected, rows.Single(v => v.AdvisoryId == $"CVE-2-{s}").Status);
            Assert.Equal("reachable", rows.Single(v => v.AdvisoryId == $"CVE-2-{s}").ImpactStatement);
            Assert.Equal(2, rows.Count(v => v.AdvisoryId == $"CVE-3-{s}"));
            Assert.Equal(VexJustification.VulnerableCodeNotPresent, rows.First(v => v.AdvisoryId == $"CVE-3-{s}").Justification);
            Assert.Equal(VexJustification.ComponentNotPresent, rows.Single(v => v.AdvisoryId == $"CVE-4-{s}").Justification);
            Assert.Equal(VexStatementStatus.Fixed, rows.Single(v => v.AdvisoryId == $"CVE-5-{s}").Status);
            Assert.Equal(VexJustification.VulnerableCodeNotInExecutePath, rows.Single(v => v.AdvisoryId == $"CVE-6-{s}").Justification);
            Assert.Equal(VexJustification.InlineMitigationsAlreadyExist, rows.Single(v => v.AdvisoryId == $"CVE-7-{s}").Justification);
            Assert.Equal(VexJustification.InlineMitigationsAlreadyExist, rows.Single(v => v.AdvisoryId == $"CVE-18-{s}").Justification);
            Assert.DoesNotContain(rows, v => v.AdvisoryId == $"CVE-8-{s}");
            Assert.DoesNotContain(rows, v => v.AdvisoryId == $"CVE-15-{s}");
        }

        // Importing the same document again updates the active rows instead of duplicating them.
        var again = await BodyAsync(await w.Admin.PostAsync(url, Json(doc)));
        Assert.Equal(0, again.GetProperty("created").GetInt32());
        Assert.Equal(13, again.GetProperty("updated").GetInt32());
    }

    [SkippableFact]
    public async Task Cyclonedx_import_rejects_bad_documents_and_denied_actors()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        var url = $"/projects/{w.Tree.ProjectId}/vex-statements/ingest-cdx";

        Assert.Equal(HttpStatusCode.BadRequest, (await w.Admin.PostAsync(url, Json("{ not json"))).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await w.Admin.PostAsync(url, Json("{}"))).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await w.Admin.PostAsync(url, Json("""{"vulnerabilities": 3}"""))).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await w.Admin.PostAsync($"/projects/{Guid.NewGuid()}/vex-statements/ingest-cdx", Json("{}"))).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Http(_fx, null).PostAsync(url, Json("{}"))).StatusCode);

        var suppressing = """{"vulnerabilities":[{"id":"CVE-X","analysis":{"state":"resolved"},"affects":[{"ref":"pkg:nuget/Foo"}]}]}""";
        var denied = await w.LeadDev.PostAsync(url, Json(suppressing));
        Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);

        // An empty list is fine and writes nothing.
        var empty = await BodyAsync(await w.Admin.PostAsync(url, Json("""{"vulnerabilities":[]}""")));
        Assert.Equal(0, empty.GetProperty("created").GetInt32());
    }
}
