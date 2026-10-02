using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Api.Contracts;
using Tamp.Findings.Api.Endpoints;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Integration.Tests;

[Collection(DatabaseCollection.Name)]
public class ApiBDastTests
{
    private readonly DatabaseFixture _fx;
    public ApiBDastTests(DatabaseFixture fx) => _fx = fx;

    private static Finding Dast(Guid cv, ScannerKind scanner, string rule, Severity sev, string url, FindingStatus status = FindingStatus.Open) => new()
    {
        ComponentVersionId = cv, Hash = Guid.NewGuid().ToString("N"), Scanner = scanner, RuleId = rule,
        Severity = sev, Title = $"t-{rule}", Description = "d", FilePath = url, Snippet = "evidence", Status = status,
    };

    [SkippableFact]
    public async Task Anonymous_is_unauthorized()
    {
        Skip.IfNot(_fx.Available);
        var anon = _fx.Factory!.WithTestAuth().As(null);

        Assert.Equal(HttpStatusCode.Unauthorized, (await anon.GetAsync("/findings/dast-tree")).StatusCode);
    }

    [SkippableFact]
    public async Task An_empty_project_returns_a_zero_tree()
    {
        Skip.IfNot(_fx.Available);
        var s = ApiBSupport.Suffix();
        ApiBSupport.World w;
        using (var scope = _fx.Scope()) w = await ApiBSupport.SeedWorldAsync(_fx.Db(scope), s);
        var admin = _fx.Factory!.WithTestAuth().As(w.AdminId);

        var tree = (await admin.GetFromJsonAsync<DastTreeResponse>($"/findings/dast-tree?projectId={w.ProjectId}", ApiBSupport.Json))!;

        Assert.Equal(0, tree.TotalCount);
        Assert.Empty(tree.Hosts);
    }

    [SkippableFact]
    public async Task Findings_group_by_host_then_route_with_severity_counts_and_only_open_dast()
    {
        Skip.IfNot(_fx.Available);
        var s = ApiBSupport.Suffix();
        ApiBSupport.World w;
        Guid cv;
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            w = await ApiBSupport.SeedWorldAsync(db, s);
            cv = await ApiBSupport.SeedBuildAsync(db, w.ProjectId);
            db.Findings.AddRange(
                Dast(cv, ScannerKind.Zap, "10020", Severity.Medium, "https://app-a.test/api/users/123?x=1"),
                Dast(cv, ScannerKind.Zap, "10021", Severity.High, "https://app-a.test/api/users/456?x=2"),
                Dast(cv, ScannerKind.Nuclei, "cve-1", Severity.Critical, "https://app-b.test/login"),
                Dast(cv, ScannerKind.Zap, "low", Severity.Low, "https://app-b.test/static"),
                Dast(cv, ScannerKind.Zap, "info", Severity.Info, "https://app-b.test/robots.txt"),
                // Excluded: closed status and a non-DAST scanner.
                Dast(cv, ScannerKind.Zap, "closed", Severity.High, "https://app-c.test/x", FindingStatus.Fixed),
                Dast(cv, ScannerKind.OpenGrep, "sast", Severity.High, "src/a.cs"));
            await db.SaveChangesAsync();
        }
        var admin = _fx.Factory!.WithTestAuth().As(w.AdminId);

        var tree = (await admin.GetFromJsonAsync<DastTreeResponse>($"/findings/dast-tree?projectId={w.ProjectId}", ApiBSupport.Json))!;

        Assert.Equal(5, tree.TotalCount);
        Assert.Equal(1, tree.Counts.Critical);
        Assert.Equal(1, tree.Counts.High);
        Assert.Equal(1, tree.Counts.Medium);
        Assert.Equal(1, tree.Counts.Low);
        Assert.Equal(1, tree.Counts.Info);
        Assert.Equal(2, tree.Hosts.Count);
        // Worst host first.
        Assert.Equal(Severity.Critical, tree.Hosts[0].MaxSeverity);
        Assert.Equal("app-b.test", tree.Hosts[0].Host, ignoreCase: true);
        var a = tree.Hosts.Single(h => h.Host.Contains("app-a", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(2, a.Routes.Sum(r => r.Findings.Count));
        Assert.Equal(Severity.High, a.MaxSeverity);
        Assert.Equal(Severity.High, a.Routes[0].MaxSeverity);   // worst route first

        // Scope filters: client, a foreign project, and latest=false all answer.
        var byClient = (await admin.GetFromJsonAsync<DastTreeResponse>($"/findings/dast-tree?clientId={w.ClientId}", ApiBSupport.Json))!;
        Assert.Equal(5, byClient.TotalCount);
        var all = (await admin.GetFromJsonAsync<DastTreeResponse>($"/findings/dast-tree?projectId={w.ProjectId}&latest=false", ApiBSupport.Json))!;
        Assert.Equal(5, all.TotalCount);
    }

    [SkippableFact]
    public async Task Latest_only_considers_the_newest_main_build_and_skips_pull_requests()
    {
        Skip.IfNot(_fx.Available);
        var s = ApiBSupport.Suffix();
        ApiBSupport.World w;
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            w = await ApiBSupport.SeedWorldAsync(db, s);
            var oldCv = new ComponentVersion { ProjectId = w.ProjectId, VersionString = "1", BranchName = "main", CreatedAt = DateTimeOffset.UtcNow.AddDays(-2) };
            var newCv = new ComponentVersion { ProjectId = w.ProjectId, VersionString = "2", BranchName = "main", CreatedAt = DateTimeOffset.UtcNow.AddDays(-1) };
            var prCv = new ComponentVersion { ProjectId = w.ProjectId, VersionString = "3", BranchName = "feat", PullRequestRef = "pr/1", CreatedAt = DateTimeOffset.UtcNow };
            db.ComponentVersions.AddRange(oldCv, newCv, prCv);
            db.Findings.AddRange(
                Dast(oldCv.Id, ScannerKind.Zap, "old", Severity.High, "https://h.test/old"),
                Dast(newCv.Id, ScannerKind.Zap, "new", Severity.High, "https://h.test/new"),
                Dast(prCv.Id, ScannerKind.Zap, "pr", Severity.High, "https://h.test/pr"));
            await db.SaveChangesAsync();
        }
        var admin = _fx.Factory!.WithTestAuth().As(w.AdminId);

        var latest = (await admin.GetFromJsonAsync<DastTreeResponse>($"/findings/dast-tree?projectId={w.ProjectId}", ApiBSupport.Json))!;
        Assert.Equal(1, latest.TotalCount);
        Assert.Equal("new", latest.Hosts[0].Routes[0].Findings[0].RuleId);

        var everything = (await admin.GetFromJsonAsync<DastTreeResponse>($"/findings/dast-tree?projectId={w.ProjectId}&latest=false", ApiBSupport.Json))!;
        Assert.Equal(3, everything.TotalCount);
    }

    [SkippableFact]
    public async Task A_user_outside_the_project_gets_404()
    {
        Skip.IfNot(_fx.Available);
        var s = ApiBSupport.Suffix();
        ApiBSupport.World w;
        using (var scope = _fx.Scope()) w = await ApiBSupport.SeedWorldAsync(_fx.Db(scope), s);
        var outsider = _fx.Factory!.WithTestAuth().As(w.OutsiderId);

        Assert.Equal(HttpStatusCode.NotFound, (await outsider.GetAsync($"/findings/dast-tree?projectId={w.ProjectId}")).StatusCode);
    }
}

[Collection(DatabaseCollection.Name)]
public class ApiBTestResultsTests
{
    private readonly DatabaseFixture _fx;
    public ApiBTestResultsTests(DatabaseFixture fx) => _fx = fx;

    private static TestSuiteRequestDto Suite(string asm, string cls, int passed, int failed, int skipped = 0) =>
        new(asm, cls, passed + failed + skipped, passed, failed, skipped, 0, 5,
        [
            new TestCaseRequestDto($"{cls}.ok", TestOutcome.Passed, 1, null, null),
            new TestCaseRequestDto($"{cls}.bad", failed > 0 ? TestOutcome.Failed : TestOutcome.Passed, 1,
                failed > 0 ? "boom" : null, failed > 0 ? "at X" : null),
        ]);

    private static TestResultsIngestRequest Req(string client, string project, string version, string sha, params TestSuiteRequestDto[] suites) =>
        new(client, project, null, null, null, version, sha, "main", null, null, "dotnet test", null,
            0, 0, 0, 0, 0, 0, DateTimeOffset.UtcNow.AddSeconds(-5), DateTimeOffset.UtcNow, suites);

    private async Task<(ApiBSupport.World w, string token)> ArrangeAsync()
    {
        var s = ApiBSupport.Suffix();
        ApiBSupport.World w;
        using var scope = _fx.Scope();
        w = await ApiBSupport.SeedWorldAsync(_fx.Db(scope), s);
        var token = await ApiBSupport.MintProjectTokenAsync(scope.ServiceProvider, w.ProjectId, w.AdminId);
        return (w, token);
    }

    [SkippableFact]
    public async Task Ingest_requires_a_token_and_the_hierarchy_fields()
    {
        Skip.IfNot(_fx.Available);
        var (w, token) = await ArrangeAsync();

        var anon = _fx.Factory!.CreateClient();
        Assert.Equal(HttpStatusCode.Unauthorized,
            (await anon.PostAsJsonAsync("/ingest/test-results", Req(w.ClientName, w.ProjectName, "1", "sha"))).StatusCode);

        var http = _fx.Factory!.Bearer(token);
        Assert.Equal(HttpStatusCode.BadRequest, (await http.PostAsJsonAsync("/ingest/test-results", Req("", w.ProjectName, "1", "sha"))).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await http.PostAsJsonAsync("/ingest/test-results", Req(w.ClientName, " ", "1", "sha"))).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await http.PostAsJsonAsync("/ingest/test-results", Req(w.ClientName, w.ProjectName, "", "sha"))).StatusCode);
    }

    [SkippableFact]
    public async Task A_token_for_another_project_cannot_ingest_here()
    {
        Skip.IfNot(_fx.Available);
        var (w, _) = await ArrangeAsync();
        var (_, otherToken) = await ArrangeAsync();

        var resp = await _fx.Factory!.Bearer(otherToken)
            .PostAsJsonAsync("/ingest/test-results", Req(w.ClientName, w.ProjectName, "1", "sha"));

        Assert.True(resp.StatusCode is HttpStatusCode.Forbidden or HttpStatusCode.Unauthorized or HttpStatusCode.NotFound or HttpStatusCode.BadRequest,
            $"unexpected {resp.StatusCode}");
        Assert.NotEqual(HttpStatusCode.OK, resp.StatusCode);
    }

    [SkippableFact]
    public async Task Tree_and_suite_endpoints_report_ingested_results_and_audit_the_ingest()
    {
        Skip.IfNot(_fx.Available);
        var (w, token) = await ArrangeAsync();
        var http = _fx.Factory!.Bearer(token);
        var sha = $"tr{ApiBSupport.Suffix()}";

        var resp = await http.PostAsJsonAsync("/ingest/test-results",
            Req(w.ClientName, w.ProjectName, "1.0.0", sha,
                Suite("A.dll", "A.Calc", 3, 1, 1), Suite("B.dll", "B.Svc", 2, 0)));
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var admin = _fx.Factory!.WithTestAuth().As(w.AdminId);

        var tree = (await admin.GetFromJsonAsync<TestResultsTreeResponse>($"/test-results/tree?projectId={w.ProjectId}", ApiBSupport.Json))!;
        Assert.True(tree.Measured);
        Assert.Equal(7, tree.TotalCount);
        Assert.Equal(1, tree.FailedCount);
        Assert.Equal(2, tree.Assemblies.Count);
        // Failing assembly sorts first.
        Assert.Equal("A.dll", tree.Assemblies[0].Name);
        Assert.Equal("A.Calc", tree.Assemblies[0].Suites[0].ClassName);

        var byClient = (await admin.GetFromJsonAsync<TestResultsTreeResponse>($"/test-results/tree?clientId={w.ClientId}&latest=false", ApiBSupport.Json))!;
        Assert.True(byClient.Measured);

        var suite = (await admin.GetFromJsonAsync<TestSuiteDetailResponse>($"/test-results/suite/{tree.Assemblies[0].Suites[0].Id}", ApiBSupport.Json))!;
        Assert.Equal("A.Calc", suite.ClassName);
        Assert.Equal(TestOutcome.Failed, suite.Cases[0].Outcome);   // failures first
        Assert.Equal("boom", suite.Cases[0].ErrorMessage);

        Assert.Equal(HttpStatusCode.NotFound, (await admin.GetAsync($"/test-results/suite/{Guid.NewGuid()}")).StatusCode);

        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        Assert.True(await db.AuditEntries.AnyAsync(a => a.Detail != null && a.Detail.Contains("test-results: 2 suites")));
    }

    [SkippableFact]
    public async Task Tree_is_unmeasured_for_a_project_with_no_results_and_anonymous_is_refused()
    {
        Skip.IfNot(_fx.Available);
        var (w, _) = await ArrangeAsync();
        var admin = _fx.Factory!.WithTestAuth().As(w.AdminId);

        var tree = (await admin.GetFromJsonAsync<TestResultsTreeResponse>($"/test-results/tree?projectId={w.ProjectId}", ApiBSupport.Json))!;
        Assert.False(tree.Measured);
        Assert.Empty(tree.Assemblies);

        var anon = _fx.Factory!.WithTestAuth().As(null);
        Assert.Equal(HttpStatusCode.Unauthorized, (await anon.GetAsync("/test-results/tree")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await anon.GetAsync($"/test-results/suite/{Guid.NewGuid()}")).StatusCode);

        var outsider = _fx.Factory!.WithTestAuth().As(w.OutsiderId);
        Assert.Equal(HttpStatusCode.NotFound, (await outsider.GetAsync($"/test-results/tree?projectId={w.ProjectId}")).StatusCode);
    }

    private const string Junit = """
        <testsuites><testsuite name="Svc.Tests" tests="2" failures="1" time="0.5">
          <testcase classname="Svc.Tests.Calc" name="adds" time="0.1"/>
          <testcase classname="Svc.Tests.Calc" name="divides" time="0.2"><failure message="div by zero">trace</failure></testcase>
        </testsuite></testsuites>
        """;

    private async Task<HttpResponseMessage> PostRaw(HttpClient http, string query, string body, string contentType = "application/xml")
    {
        var content = new StringContent(body, Encoding.UTF8, contentType);
        return await http.PostAsync($"/ingest/test-results/raw?{query}", content);
    }

    [SkippableFact]
    public async Task Raw_endpoint_validates_query_and_body()
    {
        Skip.IfNot(_fx.Available);
        var (w, token) = await ArrangeAsync();
        var http = _fx.Factory!.Bearer(token);
        var c = Uri.EscapeDataString(w.ClientName);
        var p = Uri.EscapeDataString(w.ProjectName);

        Assert.Equal(HttpStatusCode.BadRequest, (await PostRaw(http, $"project={p}&version=1", Junit)).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await PostRaw(http, $"client={c}&version=1", Junit)).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await PostRaw(http, $"client={c}&project={p}", Junit)).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await PostRaw(http, $"client={c}&project={p}&version=1", "<<not xml")).StatusCode);
        var unknown = await PostRaw(http, $"client={c}&project={p}&version=1", "<other/>");
        Assert.Equal(HttpStatusCode.BadRequest, unknown.StatusCode);
        Assert.Contains("unrecognised", await unknown.Content.ReadAsStringAsync(), StringComparison.Ordinal);

        var anon = _fx.Factory!.CreateClient();
        Assert.Equal(HttpStatusCode.Unauthorized, (await PostRaw(anon, $"client={c}&project={p}&version=1", Junit)).StatusCode);
    }

    [SkippableFact]
    public async Task Raw_junit_is_parsed_stored_and_keeps_the_raw_artifact()
    {
        Skip.IfNot(_fx.Available);
        var (w, token) = await ArrangeAsync();
        var http = _fx.Factory!.Bearer(token);
        var sha = $"raw{ApiBSupport.Suffix()}";

        var resp = await PostRaw(http,
            $"client={Uri.EscapeDataString(w.ClientName)}&project={Uri.EscapeDataString(w.ProjectName)}&version=1&commitSha={sha}&filename=junit.xml", Junit);

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var body = (await resp.Content.ReadFromJsonAsync<TestResultsIngestResponse>(ApiBSupport.Json))!;
        Assert.Equal(1, body.SuitesCount);
        Assert.Equal(2, body.CasesCount);

        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        Assert.True(await db.RawReportArtifacts.AnyAsync(a => a.ComponentVersionId == body.ComponentVersionId && a.FileName == "junit.xml"));
        var report = await db.TestRunReports.SingleAsync(r => r.Id == body.TestRunReportId);
        Assert.Equal(1, report.FailedCount);
    }
}
