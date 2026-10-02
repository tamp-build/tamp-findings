using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;
using static Tamp.Findings.Integration.Tests.ApiAHarness;

namespace Tamp.Findings.Integration.Tests;

// POST/GET /suppressions, DELETE /suppressions/{id}
[Collection(DatabaseCollection.Name)]
public class ApiASuppressionsTests
{
    private readonly DatabaseFixture _fx;
    public ApiASuppressionsTests(DatabaseFixture fx) => _fx = fx;

    private sealed record World(Tree Tree, Guid AdminId, HttpClient Admin, HttpClient Auditor, HttpClient LeadDev, Guid LeadDevId, Guid FindingId, Guid CvId);

    private async Task<World> SeedAsync()
    {
        var tree = await ClientProjectAsync(_fx);
        var cv = await VersionAsync(_fx, tree.ProjectId, "1." + Sfx(), branch: null);
        var finding = NewFinding(cv, ScannerKind.Roslyn, Severity.High, "CA-" + Sfx(), path: "src/A.cs", line: 1);
        await AddFindingsAsync(_fx, finding);
        var adminId = await UserAsync(_fx, admin: true);
        var auditor = await UserAsync(_fx, admin: false);
        await GrantAsync(_fx, auditor, ProjectRole.Auditor, tree.ClientId, null);
        var lead = await UserAsync(_fx, admin: false);
        await GrantAsync(_fx, lead, ProjectRole.LeadDev, null, tree.ProjectId);
        return new World(tree, adminId, Http(_fx, adminId), Http(_fx, auditor), Http(_fx, lead), lead, finding.Id, cv);
    }

    private static object Req(SuppressionScope scope, Guid? findingId = null, string? ruleId = null, string? filePath = null,
        string reason = "accepted by design", DateTimeOffset? expires = null, Guid? projectId = null, bool noExpiry = false) => new
    {
        scope = scope.ToString(), findingId, ruleId, filePath, reason,
        expiresAt = noExpiry ? (DateTimeOffset?)null : (expires ?? DateTimeOffset.UtcNow.AddDays(30)), projectId,
    };

    private static async Task<JsonElement> BodyAsync(HttpResponseMessage r) => (await JsonAsync(r)).RootElement.Clone();

    // ---------------------------------------------------------------- create

    [SkippableFact]
    public async Task Create_single_finding_suppression_binds_the_row_to_the_findings_project()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();

        var resp = await w.Admin.PostAsJsonAsync("/suppressions", Req(SuppressionScope.SingleFinding, findingId: w.FindingId));

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var s = await BodyAsync(resp);
        Assert.Equal("SingleFinding", s.GetProperty("scope").GetString());
        Assert.Equal(w.FindingId, s.GetProperty("findingId").GetGuid());
        Assert.True(s.GetProperty("isActive").GetBoolean());
        Assert.Equal("Architect", s.GetProperty("createdByRole").GetString());   // an instance admin is recorded as the closest project authority
        Assert.Equal(w.AdminId, s.GetProperty("createdByUserId").GetGuid());

        using var scope = _fx.Scope();
        var row = await _fx.Db(scope).Suppressions.AsNoTracking().SingleAsync(x => x.Id == s.GetProperty("id").GetGuid());
        Assert.Equal(w.Tree.ProjectId, row.ProjectId);
        Assert.Equal(w.Tree.ClientId, row.ClientId);
    }

    [SkippableFact]
    public async Task Create_rule_scoped_suppressions_require_a_project_and_their_fields()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        var rule = "R-" + Sfx();

        // RuleOnFile
        var ok = await w.Admin.PostAsJsonAsync("/suppressions", Req(SuppressionScope.RuleOnFile, ruleId: rule, filePath: "src/A.cs", projectId: w.Tree.ProjectId));
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        Assert.Equal("src/A.cs", (await BodyAsync(ok)).GetProperty("filePath").GetString());
        Assert.Equal(HttpStatusCode.BadRequest, (await w.Admin.PostAsJsonAsync("/suppressions", Req(SuppressionScope.RuleOnFile, filePath: "x", projectId: w.Tree.ProjectId))).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await w.Admin.PostAsJsonAsync("/suppressions", Req(SuppressionScope.RuleOnFile, ruleId: rule, projectId: w.Tree.ProjectId))).StatusCode);
        var noProject = await w.Admin.PostAsJsonAsync("/suppressions", Req(SuppressionScope.RuleOnFile, ruleId: rule, filePath: "src/A.cs"));
        Assert.Equal(HttpStatusCode.BadRequest, noProject.StatusCode);
        Assert.Contains("projectId", await noProject.Content.ReadAsStringAsync());

        // RuleEverywhere
        Assert.Equal(HttpStatusCode.OK, (await w.Admin.PostAsJsonAsync("/suppressions", Req(SuppressionScope.RuleEverywhere, ruleId: rule, projectId: w.Tree.ProjectId))).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await w.Admin.PostAsJsonAsync("/suppressions", Req(SuppressionScope.RuleEverywhere, projectId: w.Tree.ProjectId))).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await w.Admin.PostAsJsonAsync("/suppressions", Req(SuppressionScope.RuleEverywhere, ruleId: rule))).StatusCode);

        // SingleFinding needs the finding id
        Assert.Equal(HttpStatusCode.BadRequest, (await w.Admin.PostAsJsonAsync("/suppressions", Req(SuppressionScope.SingleFinding))).StatusCode);
    }

    [SkippableFact]
    public async Task Create_requires_reason_and_a_future_expiry()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();

        var noReason = await w.Admin.PostAsJsonAsync("/suppressions", Req(SuppressionScope.SingleFinding, findingId: w.FindingId, reason: "  "));
        Assert.Equal(HttpStatusCode.BadRequest, noReason.StatusCode);
        Assert.Contains("reason", await noReason.Content.ReadAsStringAsync());

        var noExpiry = await w.Admin.PostAsJsonAsync("/suppressions", Req(SuppressionScope.SingleFinding, findingId: w.FindingId, noExpiry: true));
        Assert.Equal(HttpStatusCode.BadRequest, noExpiry.StatusCode);
        Assert.Contains("expiresAt", await noExpiry.Content.ReadAsStringAsync());

        var past = await w.Admin.PostAsJsonAsync("/suppressions", Req(SuppressionScope.SingleFinding, findingId: w.FindingId, expires: DateTimeOffset.UtcNow.AddDays(-1)));
        Assert.Equal(HttpStatusCode.BadRequest, past.StatusCode);
        Assert.Contains("past", await past.Content.ReadAsStringAsync());
    }

    [SkippableFact]
    public async Task Create_is_gated_by_the_authenticated_users_capability_at_the_target_scope()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        var other = await SeedAsync();

        Assert.Equal(HttpStatusCode.Unauthorized,
            (await Http(_fx, null).PostAsJsonAsync("/suppressions", Req(SuppressionScope.SingleFinding, findingId: w.FindingId))).StatusCode);

        // Auditor: read-only role
        Assert.Equal(HttpStatusCode.Forbidden,
            (await w.Auditor.PostAsJsonAsync("/suppressions", Req(SuppressionScope.SingleFinding, findingId: w.FindingId))).StatusCode);

        // Lead Dev on this project: allowed here, with their role recorded; not on another project's finding.
        var ok = await w.LeadDev.PostAsJsonAsync("/suppressions", Req(SuppressionScope.SingleFinding, findingId: w.FindingId));
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        Assert.Equal("LeadDev", (await BodyAsync(ok)).GetProperty("createdByRole").GetString());
        Assert.Equal(HttpStatusCode.Forbidden,
            (await w.LeadDev.PostAsJsonAsync("/suppressions", Req(SuppressionScope.SingleFinding, findingId: other.FindingId))).StatusCode);

        // A finding that does not exist resolves to instance scope, which only an admin reaches.
        Assert.Equal(HttpStatusCode.Forbidden,
            (await w.LeadDev.PostAsJsonAsync("/suppressions", Req(SuppressionScope.SingleFinding, findingId: Guid.NewGuid()))).StatusCode);

        // A user row that is not approved is refused.
        var unapproved = await UserAsync(_fx, admin: false, approved: false);
        Assert.Equal(HttpStatusCode.Forbidden,
            (await Http(_fx, unapproved).PostAsJsonAsync("/suppressions", Req(SuppressionScope.SingleFinding, findingId: w.FindingId))).StatusCode);
    }

    // ---------------------------------------------------------------- list

    [SkippableFact]
    public async Task List_filters_active_rule_and_project_with_client_and_instance_wide_rows()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        var other = await SeedAsync();
        var rule = "LR-" + Sfx();
        var otherRule = "LO-" + Sfx();
        var now = DateTimeOffset.UtcNow;

        Guid userId = w.AdminId;
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            Suppression S(string r, Guid? client, Guid? project, DateTimeOffset? exp, DateTimeOffset created, Guid? by = null) => new()
            {
                Scope = SuppressionScope.RuleEverywhere, RuleId = r, ClientId = client, ProjectId = project,
                CreatedByUserId = by ?? userId, CreatedByRole = ProjectRole.Architect, Reason = "r", ExpiresAt = exp, CreatedAt = created,
            };
            db.Suppressions.AddRange(
                S(rule, w.Tree.ClientId, w.Tree.ProjectId, now.AddDays(5), now.AddMinutes(-3)),     // project row
                S(rule, w.Tree.ClientId, null, now.AddDays(5), now.AddMinutes(-2)),                 // client row (applies to the project)
                S(rule, null, null, null, now.AddMinutes(-1)),                                      // legacy instance-wide, no expiry
                S(rule, other.Tree.ClientId, other.Tree.ProjectId, now.AddDays(5), now),            // someone else's
                S(rule, w.Tree.ClientId, w.Tree.ProjectId, now.AddDays(-1), now.AddMinutes(-9)),    // expired
                S(otherRule, w.Tree.ClientId, w.Tree.ProjectId, now.AddDays(5), now.AddMinutes(-4), by: Guid.NewGuid()));   // author no longer exists
            await db.SaveChangesAsync();
        }
        var http = w.Admin;

        var forProject = await GetJsonAsync(http, $"/suppressions?projectId={w.Tree.ProjectId}&ruleId={rule}");
        Assert.Equal(3, forProject.GetArrayLength());   // project + client + instance-wide; not the other tenant's, not the expired
        Assert.All(forProject.EnumerateArray(), x => Assert.True(x.GetProperty("isActive").GetBoolean()));
        // newest first: instance-wide (-1m), client (-2m), project (-3m)
        Assert.Equal(JsonValueKind.Null, forProject[0].GetProperty("expiresAt").ValueKind);

        var includingExpired = await GetJsonAsync(http, $"/suppressions?projectId={w.Tree.ProjectId}&ruleId={rule}&activeOnly=false");
        Assert.Equal(4, includingExpired.GetArrayLength());
        Assert.Contains(includingExpired.EnumerateArray(), x => !x.GetProperty("isActive").GetBoolean());

        var byRuleOnly = await GetJsonAsync(http, $"/suppressions?ruleId={rule}");
        Assert.Equal(4, byRuleOnly.GetArrayLength());   // every active row for the rule, any tenant

        var unknownAuthor = await GetJsonAsync(http, $"/suppressions?ruleId={otherRule}");
        Assert.Equal("(unknown)", Assert.Single(unknownAuthor.EnumerateArray()).GetProperty("createdByUserLogin").GetString());

        // Naming a project outside the boundary is a 404; anonymous is a 401.
        Assert.Equal(HttpStatusCode.NotFound, (await w.LeadDev.GetAsync($"/suppressions?projectId={other.Tree.ProjectId}")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await w.LeadDev.GetAsync($"/suppressions?projectId={w.Tree.ProjectId}")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Http(_fx, null).GetAsync("/suppressions")).StatusCode);
    }

    // ---------------------------------------------------------------- delete

    [SkippableFact]
    public async Task Delete_withdraws_the_suppression_and_reopens_the_finding()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        var created = await BodyAsync(await w.Admin.PostAsJsonAsync("/suppressions", Req(SuppressionScope.SingleFinding, findingId: w.FindingId)));
        var id = created.GetProperty("id").GetGuid();
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            (await db.Findings.SingleAsync(f => f.Id == w.FindingId)).Status = FindingStatus.Suppressed;
            await db.SaveChangesAsync();
        }

        Assert.Equal(HttpStatusCode.NotFound, (await w.Admin.DeleteAsync($"/suppressions/{Guid.NewGuid()}")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Http(_fx, null).DeleteAsync($"/suppressions/{id}")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await w.Auditor.DeleteAsync($"/suppressions/{id}")).StatusCode);
        var unapproved = await UserAsync(_fx, admin: false, approved: false);
        Assert.Equal(HttpStatusCode.Forbidden, (await Http(_fx, unapproved).DeleteAsync($"/suppressions/{id}")).StatusCode);

        Assert.Equal(HttpStatusCode.NoContent, (await w.LeadDev.DeleteAsync($"/suppressions/{id}")).StatusCode);

        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            var row = await db.Suppressions.AsNoTracking().SingleAsync(x => x.Id == id);
            Assert.True(row.ExpiresAt <= DateTimeOffset.UtcNow);      // expired, not deleted
            Assert.Equal(FindingStatus.Open, (await db.Findings.AsNoTracking().SingleAsync(f => f.Id == w.FindingId)).Status);
            Assert.True(await db.AuditEntries.AnyAsync(a => a.SubjectId == id && a.Action == "suppression.withdrawn"));
        }

        // Withdrawing an already-withdrawn suppression is idempotent.
        Assert.Equal(HttpStatusCode.NoContent, (await w.Admin.DeleteAsync($"/suppressions/{id}")).StatusCode);
        var active = await GetJsonAsync(w.Admin, $"/suppressions?projectId={w.Tree.ProjectId}");
        Assert.DoesNotContain(active.EnumerateArray(), x => x.GetProperty("id").GetGuid() == id);
    }
}
