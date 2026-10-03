using Microsoft.Extensions.DependencyInjection;
using System.Net;
using System.Text.Json;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;
using static Tamp.Findings.Integration.Tests.ApiAHarness;

namespace Tamp.Findings.Integration.Tests;

// GET /findings, /clients, /projects, /findings/tree, /findings/file
[Collection(DatabaseCollection.Name)]
public class ApiAFindingsQueryTests
{
    private readonly DatabaseFixture _fx;
    public ApiAFindingsQueryTests(DatabaseFixture fx) => _fx = fx;

    private sealed record World(Tree Tree, Guid Admin, Guid CvOld, Guid CvNew, Guid CvLinux);

    private async Task<World> SeedAsync()
    {
        var admin = await UserAsync(_fx, admin: true);
        var tree = await ClientProjectAsync(_fx);
        var s = Sfx();
        var now = DateTimeOffset.UtcNow;
        var cvOld = await VersionAsync(_fx, tree.ProjectId, $"1.{s}", createdAt: now.AddDays(-3));
        var cvNew = await VersionAsync(_fx, tree.ProjectId, $"2.{s}", createdAt: now.AddHours(-1));
        var cvLinux = await VersionAsync(_fx, tree.ProjectId, $"2.{s}-l", flavor: "linux", createdAt: now.AddHours(-2));

        Finding F(Guid cv, ScannerKind sc, Severity sev, string rule, FindingStatus st = FindingStatus.Open,
                  string? path = null, int? line = null, string? title = null, DateTimeOffset? lastSeen = null)
        {
            var f = NewFinding(cv, sc, sev, rule, st, path, line, title: title);
            if (lastSeen is { } ls) f.LastSeen = ls;
            return f;
        }

        await AddFindingsAsync(_fx,
            F(cvOld, ScannerKind.Roslyn, Severity.Critical, "OLD", path: "src/Old/Old.cs"),
            F(cvNew, ScannerKind.Roslyn, Severity.Critical, "CA-A", path: "file:///C:/repos/x/src/Tamp.Api/Foo.cs", line: 20, title: "Dangerous call", lastSeen: now.AddMinutes(-5)),
            F(cvNew, ScannerKind.Roslyn, Severity.Critical, "CA-B", path: "src\\Tamp.Api\\Foo.cs", line: 5, title: "Another dangerous", lastSeen: now.AddMinutes(-1)),
            F(cvNew, ScannerKind.Roslyn, Severity.High, "CA-C", path: "src/Tamp.Api/Bar.cs", line: 7, title: "Unused thing"),
            F(cvNew, ScannerKind.OpenGrep, Severity.High, "OG-1", path: "src/Tamp.Core/Baz.cs", line: 1, title: "Sql injection"),
            F(cvNew, ScannerKind.OpenGrep, Severity.Medium, "OG-2", path: "web/app/x.ts", line: 3),
            F(cvNew, ScannerKind.ESLint, Severity.Low, "ES-1", path: "build/Build.cs", line: 9),
            F(cvNew, ScannerKind.ESLint, Severity.Info, "ES-2", path: "docs/readme.md"),
            F(cvNew, ScannerKind.TruffleHog, Severity.High, "TH-1"),                                   // no path
            F(cvNew, ScannerKind.Roslyn, Severity.Medium, "CA-S", FindingStatus.Suppressed, path: "src/Tamp.Api/Foo.cs", line: 40),
            F(cvNew, ScannerKind.Roslyn, Severity.Low, "CA-F", FindingStatus.Fixed, path: "src/Tamp.Api/Foo.cs", line: 41),
            F(cvLinux, ScannerKind.OpenGrep, Severity.Critical, "OG-L", path: "src/Tamp.Core/Baz.cs", line: 2, lastSeen: now.AddHours(-1)));

        // CA-S is Suppressed, so a suppression has to actually COVER it. Without one, the SuppressionExpiryWorker
        // (which sweeps shortly after the host starts, then periodically) legitimately reopens it, and on a slow
        // runner that landed between this seed and the assertions, turning the expected 10 open into 11.
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            db.Suppressions.Add(new Suppression
            {
                Scope = SuppressionScope.RuleEverywhere, RuleId = "CA-S",
                ClientId = tree.ClientId, ProjectId = tree.ProjectId,
                CreatedByUserId = admin, CreatedByRole = ProjectRole.InfoSecOfficer,
                Reason = "seeded: covers the suppressed CA-S finding so the expiry sweep leaves it alone",
            });
            await db.SaveChangesAsync();
        }

        return new World(tree, admin, cvOld, cvNew, cvLinux);
    }

    private static List<string> Rules(JsonElement r) =>
        r.GetProperty("items").EnumerateArray().Select(i => i.GetProperty("ruleId").GetString()!).ToList();

    // ---------------------------------------------------------------- /findings

    [SkippableFact]
    public async Task Findings_default_is_open_only_on_the_latest_builds_sorted_by_severity_then_recency()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        var http = Http(_fx, w.Admin);

        var r = await GetJsonAsync(http, $"/findings?projectId={w.Tree.ProjectId}");

        Assert.Equal(9, r.GetProperty("totalCount").GetInt32());
        Assert.Equal(0, r.GetProperty("skip").GetInt32());
        Assert.Equal(100, r.GetProperty("take").GetInt32());
        var rules = Rules(r);
        Assert.DoesNotContain("OLD", rules);
        Assert.DoesNotContain("CA-S", rules);
        Assert.DoesNotContain("CA-F", rules);
        // Critical first; within Critical the most recently seen first.
        Assert.Equal("CA-B,CA-A", string.Join(",", rules.Take(2)));
        Assert.Equal("OG-L", rules[2]);
        var counts = r.GetProperty("counts");
        Assert.Equal(3, counts.GetProperty("critical").GetInt32());
        Assert.Equal(3, counts.GetProperty("high").GetInt32());
        Assert.Equal(1, counts.GetProperty("medium").GetInt32());
        Assert.Equal(1, counts.GetProperty("low").GetInt32());
        Assert.Equal(1, counts.GetProperty("info").GetInt32());

        var first = r.GetProperty("items")[0];
        Assert.Equal(w.Tree.ProjectName, first.GetProperty("projectName").GetString());
        Assert.Equal(w.Tree.ClientName, first.GetProperty("clientName").GetString());
        Assert.Equal(w.CvNew, first.GetProperty("componentVersionId").GetGuid());
    }

    [SkippableFact]
    public async Task Findings_filters_by_severity_scanner_status_search_and_version()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        var http = Http(_fx, w.Admin);
        var p = $"projectId={w.Tree.ProjectId}";

        var sev = await GetJsonAsync(http, $"/findings?{p}&severity=Critical,high");
        Assert.Equal(6, sev.GetProperty("totalCount").GetInt32());

        // Unknown tokens are ignored rather than rejected; empty severity list = no filter.
        var junk = await GetJsonAsync(http, $"/findings?{p}&severity=nonsense,%20,Low&scanner=");
        Assert.Equal(["ES-1"], Rules(junk));

        var scan = await GetJsonAsync(http, $"/findings?{p}&scanner=OpenGrep,ESLint");
        Assert.Equal(5, scan.GetProperty("totalCount").GetInt32());

        var sup = await GetJsonAsync(http, $"/findings?{p}&status=Suppressed");
        Assert.Equal(["CA-S"], Rules(sup));
        var mixed = await GetJsonAsync(http, $"/findings?{p}&status=open,fixed");
        Assert.Equal(10, mixed.GetProperty("totalCount").GetInt32());

        var byTitle = await GetJsonAsync(http, $"/findings?{p}&search=sql%20inj");
        Assert.Equal(["OG-1"], Rules(byTitle));
        var byRule = await GetJsonAsync(http, $"/findings?{p}&search=ca-c");
        Assert.Equal(["CA-C"], Rules(byRule));
        var blank = await GetJsonAsync(http, $"/findings?{p}&search=%20%20");
        Assert.Equal(9, blank.GetProperty("totalCount").GetInt32());

        var cv = await GetJsonAsync(http, $"/findings?componentVersionId={w.CvOld}&latest=false");
        Assert.Equal(["OLD"], Rules(cv));
        var cvLatest = await GetJsonAsync(http, $"/findings?componentVersionId={w.CvOld}");
        Assert.Equal(0, cvLatest.GetProperty("totalCount").GetInt32());

        var client = await GetJsonAsync(http, $"/findings?clientId={w.Tree.ClientId}");
        Assert.Equal(9, client.GetProperty("totalCount").GetInt32());

        var all = await GetJsonAsync(http, $"/findings?{p}&latest=false");
        Assert.Equal(10, all.GetProperty("totalCount").GetInt32());   // + OLD
    }

    [SkippableFact]
    public async Task Findings_paging_clamps_take_and_skip()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        var http = Http(_fx, w.Admin);
        var p = $"projectId={w.Tree.ProjectId}";

        var page1 = await GetJsonAsync(http, $"/findings?{p}&take=3");
        var page2 = await GetJsonAsync(http, $"/findings?{p}&take=3&skip=3");
        Assert.Equal(3, page1.GetProperty("items").GetArrayLength());
        Assert.Equal(9, page1.GetProperty("totalCount").GetInt32());
        Assert.Equal(3, page2.GetProperty("skip").GetInt32());
        Assert.Empty(Rules(page1).Intersect(Rules(page2)));

        var zero = await GetJsonAsync(http, $"/findings?{p}&take=0&skip=-4");
        Assert.Equal(1, zero.GetProperty("take").GetInt32());
        Assert.Equal(0, zero.GetProperty("skip").GetInt32());
        Assert.Equal(1, zero.GetProperty("items").GetArrayLength());

        var huge = await GetJsonAsync(http, $"/findings?{p}&take=99999");
        Assert.Equal(500, huge.GetProperty("take").GetInt32());

        var beyond = await GetJsonAsync(http, $"/findings?{p}&skip=500");
        Assert.Equal(0, beyond.GetProperty("items").GetArrayLength());
        Assert.Equal(9, beyond.GetProperty("totalCount").GetInt32());
    }

    [SkippableFact]
    public async Task Findings_unfiltered_listing_is_narrowed_to_what_the_caller_can_see()
    {
        Skip.IfNot(_fx.Available);
        var mine = await SeedAsync();
        var theirs = await SeedAsync();
        var clientMember = await UserAsync(_fx, admin: false);
        await GrantAsync(_fx, clientMember, ProjectRole.LeadDev, mine.Tree.ClientId, null);
        var projectMember = await UserAsync(_fx, admin: false);
        await GrantAsync(_fx, projectMember, ProjectRole.Architect, null, theirs.Tree.ProjectId);
        var nobody = await UserAsync(_fx, admin: false);   // approved, no grants, instance is segmented
        var unapproved = await UserAsync(_fx, admin: false, approved: false);

        var viaClient = await GetJsonAsync(Http(_fx, clientMember), "/findings?take=500");
        Assert.True(viaClient.GetProperty("totalCount").GetInt32() >= 9);
        Assert.All(viaClient.GetProperty("items").EnumerateArray(),
            i => Assert.Equal(mine.Tree.ClientId, i.GetProperty("clientId").GetGuid()));

        var viaProject = await GetJsonAsync(Http(_fx, projectMember), "/findings?take=500");
        Assert.Equal(9, viaProject.GetProperty("totalCount").GetInt32());
        Assert.All(viaProject.GetProperty("items").EnumerateArray(),
            i => Assert.Equal(theirs.Tree.ProjectId, i.GetProperty("projectId").GetGuid()));

        var none = await GetJsonAsync(Http(_fx, nobody), "/findings");
        Assert.Equal(0, none.GetProperty("totalCount").GetInt32());
        var none2 = await GetJsonAsync(Http(_fx, unapproved), "/findings");
        Assert.Equal(0, none2.GetProperty("totalCount").GetInt32());

        // Naming an id outside the boundary is a 404, not an empty list.
        var denied = await Http(_fx, clientMember).GetAsync($"/findings?projectId={theirs.Tree.ProjectId}");
        Assert.Equal(HttpStatusCode.NotFound, denied.StatusCode);
        var deniedCv = await Http(_fx, clientMember).GetAsync($"/findings?componentVersionId={theirs.CvNew}");
        Assert.Equal(HttpStatusCode.NotFound, deniedCv.StatusCode);
        var deniedNobody = await Http(_fx, nobody).GetAsync($"/findings?clientId={mine.Tree.ClientId}");
        Assert.Equal(HttpStatusCode.NotFound, deniedNobody.StatusCode);

        var anon = await Http(_fx, null).GetAsync("/findings");
        Assert.Equal(HttpStatusCode.Unauthorized, anon.StatusCode);
    }

    // ---------------------------------------------------------------- /clients, /projects

    [SkippableFact]
    public async Task Clients_and_projects_list_with_counts_and_respect_visibility()
    {
        Skip.IfNot(_fx.Available);
        var a = await SeedAsync();
        var a2 = await ClientProjectAsync(_fx, a.Tree.ClientId, a.Tree.ClientName);
        var b = await SeedAsync();
        var member = await UserAsync(_fx, admin: false);
        await GrantAsync(_fx, member, ProjectRole.LeadDev, null, b.Tree.ProjectId);   // project-tier grant only

        var admin = Http(_fx, a.Admin);
        var clients = await GetJsonAsync(admin, "/clients");
        var rowA = clients.EnumerateArray().Single(c => c.GetProperty("id").GetGuid() == a.Tree.ClientId);
        Assert.Equal(2, rowA.GetProperty("projectCount").GetInt32());
        Assert.Contains(clients.EnumerateArray(), c => c.GetProperty("id").GetGuid() == b.Tree.ClientId);

        var projects = await GetJsonAsync(admin, $"/projects?clientId={a.Tree.ClientId}");
        Assert.Equal(2, projects.GetArrayLength());
        var row = projects.EnumerateArray().Single(p => p.GetProperty("id").GetGuid() == a.Tree.ProjectId);
        Assert.Equal(3, row.GetProperty("buildCount").GetInt32());
        Assert.Equal(a.Tree.ClientName, row.GetProperty("clientName").GetString());
        var allProjects = await GetJsonAsync(admin, "/projects");
        Assert.True(allProjects.GetArrayLength() >= 3);

        // A project-tier grant still reveals its client, and only that project.
        var asMember = Http(_fx, member);
        var memberClients = await GetJsonAsync(asMember, "/clients");
        Assert.Equal(b.Tree.ClientId, Assert.Single(memberClients.EnumerateArray()).GetProperty("id").GetGuid());
        var memberProjects = await GetJsonAsync(asMember, "/projects");
        Assert.Equal(b.Tree.ProjectId, Assert.Single(memberProjects.EnumerateArray()).GetProperty("id").GetGuid());

        // A client-tier grant reaches all of that client's projects.
        var clientMember = await UserAsync(_fx, admin: false);
        await GrantAsync(_fx, clientMember, ProjectRole.Auditor, a.Tree.ClientId, null);
        var cm = await GetJsonAsync(Http(_fx, clientMember), "/projects");
        Assert.Equal(2, cm.GetArrayLength());
        var cmClients = await GetJsonAsync(Http(_fx, clientMember), "/clients");
        Assert.Single(cmClients.EnumerateArray());

        var nobody = await UserAsync(_fx, admin: false);
        Assert.Equal(0, (await GetJsonAsync(Http(_fx, nobody), "/clients")).GetArrayLength());
        Assert.Equal(0, (await GetJsonAsync(Http(_fx, nobody), "/projects")).GetArrayLength());
    }

    // ---------------------------------------------------------------- /findings/tree

    [SkippableFact]
    public async Task Tree_groups_open_findings_by_module_and_normalises_paths()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        var http = Http(_fx, w.Admin);

        var r = await GetJsonAsync(http, $"/findings/tree?projectId={w.Tree.ProjectId}");

        Assert.Equal(1, r.GetProperty("noPathCount").GetInt32());
        Assert.Equal(9, r.GetProperty("totalCount").GetInt32());   // 8 with paths + 1 without
        var modules = r.GetProperty("modules").EnumerateArray().ToList();
        // Tamp.Api: CA-A, CA-B, CA-C (3) ; Tamp.Core: OG-1, OG-L (2); then 1-finding modules by name.
        Assert.Equal(["Tamp.Api", "Tamp.Core", "(other)", "build", "web"],
            modules.Select(m => m.GetProperty("name").GetString()!).ToArray());
        var api = modules[0];
        Assert.Equal(2, api.GetProperty("counts").GetProperty("critical").GetInt32());
        Assert.Equal(1, api.GetProperty("counts").GetProperty("high").GetInt32());
        var files = api.GetProperty("files").EnumerateArray().ToList();
        Assert.Equal(["src/Tamp.Api/Foo.cs", "src/Tamp.Api/Bar.cs"],
            files.Select(f => f.GetProperty("relativePath").GetString()!).ToArray());   // worst first
        Assert.Equal("Critical", files[0].GetProperty("maxSeverity").GetString());
        Assert.Equal(2, files[0].GetProperty("counts").GetProperty("critical").GetInt32());   // file:/// and backslash forms fold together
        Assert.Equal("High", files[1].GetProperty("maxSeverity").GetString());
        Assert.Equal(3, r.GetProperty("counts").GetProperty("critical").GetInt32());
        Assert.Equal(1, r.GetProperty("counts").GetProperty("info").GetInt32());
    }

    [SkippableFact]
    public async Task The_seed_is_stable_under_the_suppression_expiry_sweep()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        var http = Http(_fx, w.Admin);

        // The SuppressionExpiryWorker runs this same sweep in the background at unpredictable moments. A
        // Suppressed finding that no suppression covers is reopened by it, which used to make the open count here
        // 11 instead of 10 whenever a tick landed mid-test. Run it explicitly and prove the seed is immune.
        using (var scope = _fx.Scope())
            await scope.ServiceProvider.GetRequiredService<Tamp.Findings.Application.Suppressions.SuppressionExpiryService>()
                .SweepAsync(DateTimeOffset.UtcNow, default);

        var everything = await GetJsonAsync(http, $"/findings/tree?projectId={w.Tree.ProjectId}&latest=false");
        Assert.Equal(10, everything.GetProperty("totalCount").GetInt32());
    }

    [SkippableFact]
    public async Task Tree_honours_rule_filter_latest_flag_and_empty_scopes()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        var http = Http(_fx, w.Admin);
        var p = $"projectId={w.Tree.ProjectId}";

        var byRule = await GetJsonAsync(http, $"/findings/tree?{p}&ruleId=CA-C");
        Assert.Equal(1, byRule.GetProperty("totalCount").GetInt32());
        Assert.Equal("Tamp.Api", byRule.GetProperty("modules")[0].GetProperty("name").GetString());

        var everything = await GetJsonAsync(http, $"/findings/tree?{p}&latest=false");
        Assert.Equal(10, everything.GetProperty("totalCount").GetInt32());   // + OLD under src/Old
        Assert.Contains(everything.GetProperty("modules").EnumerateArray(),
            m => m.GetProperty("name").GetString() == "Old");

        var client = await GetJsonAsync(http, $"/findings/tree?clientId={w.Tree.ClientId}");
        Assert.Equal(9, client.GetProperty("totalCount").GetInt32());

        var empty = await GetJsonAsync(http, $"/findings/tree?{p}&ruleId=does-not-exist");
        Assert.Equal(0, empty.GetProperty("totalCount").GetInt32());
        Assert.Equal(0, empty.GetProperty("modules").GetArrayLength());
        Assert.Equal(0, empty.GetProperty("noPathCount").GetInt32());

        var anon = await Http(_fx, null).GetAsync($"/findings/tree?{p}");
        Assert.Equal(HttpStatusCode.Unauthorized, anon.StatusCode);
    }

    // ---------------------------------------------------------------- /findings/file

    [SkippableFact]
    public async Task File_returns_findings_on_the_path_with_source_when_coverage_stored_it()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            var report = new CoverageReport { ComponentVersionId = w.CvNew, ToolName = "Coverlet" };
            db.CoverageReports.Add(report);
            db.CoverageSourceFiles.Add(new CoverageSourceFile
            {
                CoverageReportId = report.Id, RelativePath = "src/Tamp.Api/Foo.cs",
                SourceText = "class Foo {}\n", LineCount = 1,
            });
            await db.SaveChangesAsync();
        }
        var http = Http(_fx, w.Admin);

        var r = await GetJsonAsync(http, $"/findings/file?path=src/Tamp.Api/Foo.cs&projectId={w.Tree.ProjectId}");

        Assert.True(r.GetProperty("sourceAvailable").GetBoolean());
        Assert.Equal("class Foo {}\n", r.GetProperty("sourceText").GetString());
        var items = r.GetProperty("findings").EnumerateArray().ToList();
        Assert.Equal(["CA-B", "CA-A"], items.Select(i => i.GetProperty("ruleId").GetString()!).ToArray());   // by line asc
        Assert.Equal(5, items[0].GetProperty("line").GetInt32());
        Assert.Equal("Another dangerous", items[0].GetProperty("title").GetString());

        // Suppressed/fixed findings and other files are excluded; ruleId narrows further.
        var narrowed = await GetJsonAsync(http, $"/findings/file?path=src/Tamp.Api/Foo.cs&projectId={w.Tree.ProjectId}&ruleId=CA-A");
        Assert.Single(narrowed.GetProperty("findings").EnumerateArray());

        var noSource = await GetJsonAsync(http, $"/findings/file?path=src/Tamp.Core/Baz.cs&clientId={w.Tree.ClientId}");
        Assert.False(noSource.GetProperty("sourceAvailable").GetBoolean());
        Assert.Equal("", noSource.GetProperty("sourceText").GetString());
        Assert.Equal(2, noSource.GetProperty("findings").GetArrayLength());

        var oldBuild = await GetJsonAsync(http, $"/findings/file?path=src/Old/Old.cs&projectId={w.Tree.ProjectId}&latest=false");
        Assert.Single(oldBuild.GetProperty("findings").EnumerateArray());
        var oldLatest = await GetJsonAsync(http, $"/findings/file?path=src/Old/Old.cs&projectId={w.Tree.ProjectId}");
        Assert.Empty(oldLatest.GetProperty("findings").EnumerateArray());
    }

    [SkippableFact]
    public async Task File_requires_a_path()
    {
        Skip.IfNot(_fx.Available);
        var admin = await UserAsync(_fx, admin: true);
        var http = Http(_fx, admin);

        Assert.Equal(HttpStatusCode.BadRequest, (await http.GetAsync("/findings/file?path=%20%20")).StatusCode);
    }
}
