using System.Net;
using System.Text.Json;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;
using static Tamp.Findings.Integration.Tests.ApiAHarness;

namespace Tamp.Findings.Integration.Tests;

// GET /sbom-components, /sbom-components/{id}, /coverage/tree, /coverage/class/{id}
[Collection(DatabaseCollection.Name)]
public class ApiASbomCoverageTests
{
    private readonly DatabaseFixture _fx;
    public ApiASbomCoverageTests(DatabaseFixture fx) => _fx = fx;

    private sealed record World(Tree Tree, Guid Admin, Guid CvOld, Guid CvNew, Guid CvLinux, string S, SbomSeed New);

    private async Task<World> SeedSbomAsync()
    {
        var admin = await UserAsync(_fx, admin: true);
        var tree = await ClientProjectAsync(_fx);
        var s = Sfx();
        var now = DateTimeOffset.UtcNow;
        var cvOld = await VersionAsync(_fx, tree.ProjectId, $"1.{s}", createdAt: now.AddDays(-3));
        var cvNew = await VersionAsync(_fx, tree.ProjectId, $"2.{s}", createdAt: now.AddHours(-1));
        var cvLinux = await VersionAsync(_fx, tree.ProjectId, $"2.{s}-l", flavor: "linux", createdAt: now.AddHours(-2));

        var seed = await SbomAsync(_fx, cvNew, now,
            ($"pkg:nuget/Alpha{s}", "1.0.0", "MIT", null, null, [("GHSA-" + s, Severity.High), (Cve(), Severity.Low)]),
            ($"pkg:nuget/Beta{s}", "1.0.0", "Apache-2.0", "2.0.0", now.AddDays(-5), []),
            ($"pkg:npm/charlie{s}", "3.1.0", "GPL-3.0", "3.1.0", null, []),
            ($"pkg:npm/delta{s}", "1.0.0", null, null, null, []),
            ($"pkg:pypi/echo{s}", "0.9", "", null, null, []),
            ($"pkg:npm/delta{s}", "2.0.0", "MIT", null, null, []));
        await SbomAsync(_fx, cvLinux, now.AddHours(-2),
            ($"pkg:nuget/Golf{s}", "1.0.0", "MIT", null, null, []));
        await SbomAsync(_fx, cvOld, now.AddDays(-3),
            ($"pkg:nuget/Legacy{s}", "0.1.0", "MIT", null, null, [(Cve(), Severity.Critical)]));

        // dependency edges: Alpha -> Beta, Alpha -> charlie
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            var alpha = seed.ComponentIds[$"pkg:nuget/Alpha{s}"];
            db.SbomDependencies.AddRange(
                new SbomDependency { SbomSnapshotId = seed.SnapshotId, ParentComponentId = alpha, ChildComponentId = seed.ComponentIds[$"pkg:nuget/Beta{s}"] },
                new SbomDependency { SbomSnapshotId = seed.SnapshotId, ParentComponentId = alpha, ChildComponentId = seed.ComponentIds[$"pkg:npm/charlie{s}"] });
            await db.SaveChangesAsync();
        }
        return new World(tree, admin, cvOld, cvNew, cvLinux, s, seed);
    }

    private static List<string> Names(JsonElement r) =>
        r.GetProperty("items").EnumerateArray().Select(i => i.GetProperty("name").GetString()!).ToList();

    [SkippableFact]
    public async Task List_defaults_to_the_latest_snapshot_per_flavor_ordered_by_name_then_version()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedSbomAsync();
        var http = Http(_fx, w.Admin);

        var r = await GetJsonAsync(http, $"/sbom-components?projectId={w.Tree.ProjectId}");

        Assert.Equal(7, r.GetProperty("totalCount").GetInt32());    // 6 on the latest main snapshot + Golf (linux)
        Assert.Equal(2, r.GetProperty("totalVulnerabilities").GetInt32());
        var counts = r.GetProperty("counts");
        Assert.Equal(3, counts.GetProperty("nuget").GetInt32());     // Alpha, Beta, Golf
        Assert.Equal(3, counts.GetProperty("npm").GetInt32());
        Assert.Equal(1, counts.GetProperty("other").GetInt32());
        Assert.Equal(7, counts.GetProperty("total").GetInt32());

        var delta = r.GetProperty("items").EnumerateArray()
            .Where(i => i.GetProperty("name").GetString()!.StartsWith("delta")).ToList();
        Assert.Equal(["1.0.0", "2.0.0"], delta.Select(d => d.GetProperty("version").GetString()!).ToArray());   // version tiebreak

        var alpha = r.GetProperty("items").EnumerateArray().Single(i => i.GetProperty("name").GetString()!.StartsWith("Alpha"));
        Assert.Equal(2, alpha.GetProperty("vulnerabilityCount").GetInt32());
        Assert.Equal("nuget", alpha.GetProperty("ecosystem").GetString());
        Assert.Equal(w.Tree.ProjectName, alpha.GetProperty("projectName").GetString());
        Assert.Equal(w.Tree.ClientName, alpha.GetProperty("clientName").GetString());
        var echo = r.GetProperty("items").EnumerateArray().Single(i => i.GetProperty("name").GetString()!.StartsWith("echo"));
        Assert.Equal("other", echo.GetProperty("ecosystem").GetString());

        var all = await GetJsonAsync(http, $"/sbom-components?projectId={w.Tree.ProjectId}&latest=false");
        Assert.Equal(8, all.GetProperty("totalCount").GetInt32());
        Assert.Equal(3, all.GetProperty("totalVulnerabilities").GetInt32());

        var byClient = await GetJsonAsync(http, $"/sbom-components?clientId={w.Tree.ClientId}");
        Assert.Equal(7, byClient.GetProperty("totalCount").GetInt32());

        var byVersion = await GetJsonAsync(http, $"/sbom-components?componentVersionId={w.CvOld}&latest=false");
        Assert.Equal(1, byVersion.GetProperty("totalCount").GetInt32());
        var byVersionLatest = await GetJsonAsync(http, $"/sbom-components?componentVersionId={w.CvOld}");
        Assert.Equal(0, byVersionLatest.GetProperty("totalCount").GetInt32());
    }

    [SkippableFact]
    public async Task List_filters_by_ecosystem_health_license_and_search()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedSbomAsync();
        var http = Http(_fx, w.Admin);
        var p = $"projectId={w.Tree.ProjectId}";

        Assert.Equal(3, (await GetJsonAsync(http, $"/sbom-components?{p}&ecosystem=nuget")).GetProperty("totalCount").GetInt32());
        Assert.Equal(3, (await GetJsonAsync(http, $"/sbom-components?{p}&ecosystem=%20npm%20")).GetProperty("totalCount").GetInt32());
        Assert.Equal(1, (await GetJsonAsync(http, $"/sbom-components?{p}&ecosystem=pypi")).GetProperty("totalCount").GetInt32());
        Assert.Equal(0, (await GetJsonAsync(http, $"/sbom-components?{p}&ecosystem=cargo")).GetProperty("totalCount").GetInt32());

        var vulnerable = await GetJsonAsync(http, $"/sbom-components?{p}&status=Vulnerable");
        Assert.Equal(1, vulnerable.GetProperty("totalCount").GetInt32());
        Assert.StartsWith("Alpha", Names(vulnerable)[0]);
        var outdated = await GetJsonAsync(http, $"/sbom-components?{p}&status=outdated");
        Assert.Equal(1, outdated.GetProperty("totalCount").GetInt32());
        Assert.StartsWith("Beta", Names(outdated)[0]);
        var current = await GetJsonAsync(http, $"/sbom-components?{p}&status=CURRENT");
        Assert.Equal(5, current.GetProperty("totalCount").GetInt32());
        // Unknown bucket is ignored rather than returning nothing.
        Assert.Equal(7, (await GetJsonAsync(http, $"/sbom-components?{p}&status=bogus")).GetProperty("totalCount").GetInt32());

        var mit = await GetJsonAsync(http, $"/sbom-components?{p}&license=MIT");
        Assert.Equal(3, mit.GetProperty("totalCount").GetInt32());   // Alpha, delta 2.0.0, Golf
        var unknown = await GetJsonAsync(http, $"/sbom-components?{p}&license=(unknown)");
        Assert.Equal(2, unknown.GetProperty("totalCount").GetInt32());   // delta 1.0.0 (null) + echo (empty)

        var byName = await GetJsonAsync(http, $"/sbom-components?{p}&search=ALPHA");
        Assert.Equal(1, byName.GetProperty("totalCount").GetInt32());
        var byPurl = await GetJsonAsync(http, $"/sbom-components?{p}&search=pkg:pypi");
        Assert.Equal(1, byPurl.GetProperty("totalCount").GetInt32());
        Assert.Equal(7, (await GetJsonAsync(http, $"/sbom-components?{p}&search=%20")).GetProperty("totalCount").GetInt32());
    }

    [SkippableFact]
    public async Task List_paging_is_clamped()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedSbomAsync();
        var http = Http(_fx, w.Admin);
        var p = $"projectId={w.Tree.ProjectId}";

        var page = await GetJsonAsync(http, $"/sbom-components?{p}&take=3&skip=2");
        Assert.Equal(3, page.GetProperty("items").GetArrayLength());
        Assert.Equal(7, page.GetProperty("totalCount").GetInt32());
        Assert.Equal(2, page.GetProperty("skip").GetInt32());

        var clamped = await GetJsonAsync(http, $"/sbom-components?{p}&take=0&skip=-9");
        Assert.Equal(1, clamped.GetProperty("take").GetInt32());
        Assert.Equal(0, clamped.GetProperty("skip").GetInt32());
        Assert.Equal(500, (await GetJsonAsync(http, $"/sbom-components?{p}&take=5000")).GetProperty("take").GetInt32());

        Assert.Equal(HttpStatusCode.Unauthorized, (await Http(_fx, null).GetAsync("/sbom-components")).StatusCode);
    }

    [SkippableFact]
    public async Task Detail_returns_vulnerabilities_and_dependency_edges_in_both_directions()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedSbomAsync();
        var http = Http(_fx, w.Admin);
        var alpha = w.New.ComponentIds[$"pkg:nuget/Alpha{w.S}"];
        var beta = w.New.ComponentIds[$"pkg:nuget/Beta{w.S}"];

        var d = await GetJsonAsync(http, $"/sbom-components/{alpha}");

        Assert.Equal("nuget", d.GetProperty("ecosystem").GetString());
        Assert.Equal("MIT", d.GetProperty("license").GetString());
        Assert.Equal(w.CvNew, d.GetProperty("componentVersionId").GetGuid());
        Assert.Equal(2, d.GetProperty("vulnerabilities").GetArrayLength());
        var v = d.GetProperty("vulnerabilities").EnumerateArray().First(x => x.GetProperty("advisoryId").GetString()!.StartsWith("GHSA"));
        Assert.Equal("High", v.GetProperty("severity").GetString());
        Assert.Equal("9.9.9", v.GetProperty("fixedInVersion").GetString());
        Assert.Equal("OsvScanner", v.GetProperty("source").GetString());
        Assert.Equal(2, d.GetProperty("dependsOnPurls").GetArrayLength());
        Assert.Equal(0, d.GetProperty("dependentPurls").GetArrayLength());

        var b = await GetJsonAsync(http, $"/sbom-components/{beta}");
        Assert.Equal(0, b.GetProperty("dependsOnPurls").GetArrayLength());
        Assert.Contains($"pkg:nuget/Alpha{w.S}@1.0.0", b.GetProperty("dependentPurls").EnumerateArray().Select(x => x.GetString()));

        Assert.Equal(HttpStatusCode.NotFound, (await http.GetAsync($"/sbom-components/{Guid.NewGuid()}")).StatusCode);
    }

    [SkippableFact]
    public async Task Detail_reports_unknown_ecosystem_for_malformed_purls()
    {
        Skip.IfNot(_fx.Available);
        var admin = await UserAsync(_fx, admin: true);
        var tree = await ClientProjectAsync(_fx);
        var cv = await VersionAsync(_fx, tree.ProjectId, "1." + Sfx(), branch: null);
        var seed = await SbomAsync(_fx, cv, null,
            ("not-a-purl", "1", null, null, null, []),
            ("pkg:bare", "1", null, null, null, []));
        var http = Http(_fx, admin);

        foreach (var id in seed.ComponentIds.Values)
        {
            var d = await GetJsonAsync(http, $"/sbom-components/{id}");
            Assert.Equal("unknown", d.GetProperty("ecosystem").GetString());
        }
    }

    // ---------------------------------------------------------------- coverage

    private sealed record CovWorld(Tree Tree, Guid Admin, Guid ClassCore, Guid ClassOld, Guid CvOld);

    private async Task<CovWorld> SeedCoverageAsync()
    {
        var admin = await UserAsync(_fx, admin: true);
        var tree = await ClientProjectAsync(_fx);
        var s = Sfx();
        var now = DateTimeOffset.UtcNow;
        var cvOld = await VersionAsync(_fx, tree.ProjectId, $"1.{s}", createdAt: now.AddDays(-3));
        var cvNew = await VersionAsync(_fx, tree.ProjectId, $"2.{s}", createdAt: now.AddHours(-1));
        var cvLinux = await VersionAsync(_fx, tree.ProjectId, $"2.{s}-l", flavor: "linux", createdAt: now.AddHours(-2));

        Guid classCore, classOld;
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);

        CoverageReport Report(Guid cv, int cov, int tot, int covB, int totB) => new()
        {
            ComponentVersionId = cv, ToolName = "Coverlet",
            CoveredSequences = cov, TotalSequences = tot, CoveredBranches = covB, TotalBranches = totB,
            SequenceCoverage = tot == 0 ? 0 : 100.0 * cov / tot,
        };

        var rNew = Report(cvNew, 60, 100, 10, 20);
        var rLinux = Report(cvLinux, 20, 100, 0, 0);
        var rOld = Report(cvOld, 1, 100, 1, 1);
        db.CoverageReports.AddRange(rNew, rLinux, rOld);

        CoverageSourceFile Src(CoverageReport r, string path, string text) =>
            new() { CoverageReportId = r.Id, RelativePath = path, SourceText = text, LineCount = 3 };
        var srcNew = Src(rNew, "src/Core/Foo.cs", "// foo\nclass Foo {}\n");
        var srcNew2 = Src(rNew, "src/Core/Bar.cs", "class Bar {}");
        var srcLinux = Src(rLinux, "src/Core/Foo.cs", "// foo linux\nclass Foo {}\n");
        var srcOld = Src(rOld, "src/Old/Old.cs", "class Old {}");
        db.CoverageSourceFiles.AddRange(srcNew, srcNew2, srcLinux, srcOld);

        var modNew = new CoverageModule { CoverageReportId = rNew.Id, Name = "Core", CoveredSequences = 50, TotalSequences = 80 };
        var modNew2 = new CoverageModule { CoverageReportId = rNew.Id, Name = "Empty", CoveredSequences = 0, TotalSequences = 0 };
        var modLinux = new CoverageModule { CoverageReportId = rLinux.Id, Name = "core", CoveredSequences = 20, TotalSequences = 100 };
        var modOld = new CoverageModule { CoverageReportId = rOld.Id, Name = "Old", CoveredSequences = 1, TotalSequences = 1 };
        db.CoverageModules.AddRange(modNew, modNew2, modLinux, modOld);

        CoverageClass Cls(CoverageModule m, CoverageSourceFile f, string name, int cov, int tot) => new()
        {
            CoverageModuleId = m.Id, CoverageSourceFileId = f.Id, FullName = name,
            CoveredSequences = cov, TotalSequences = tot, CoveredBranches = 3, TotalBranches = 4,
            SequenceCoverage = tot == 0 ? 0 : 100.0 * cov / tot, BranchCoverage = 75,
            VisitedLines = [1, 2], UnvisitedLines = [3],
        };
        var cFoo = Cls(modNew, srcNew, "Ns.Foo", 30, 40);
        var cBar = Cls(modNew, srcNew2, "Ns.Bar", 20, 40);
        var cFooLinux = Cls(modLinux, srcLinux, "Ns.Foo", 20, 100);
        var cEmpty = Cls(modNew2, srcNew2, "Ns.Empty", 0, 0);
        var cOld = Cls(modOld, srcOld, "Ns.Old", 1, 1);
        db.CoverageClasses.AddRange(cFoo, cBar, cFooLinux, cEmpty, cOld);
        await db.SaveChangesAsync();
        classCore = cFoo.Id; classOld = cOld.Id;
        return new CovWorld(tree, admin, classCore, classOld, cvOld);
    }

    [SkippableFact]
    public async Task Coverage_tree_folds_modules_and_classes_across_the_latest_reports()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedCoverageAsync();
        var http = Http(_fx, w.Admin);

        var r = await GetJsonAsync(http, $"/coverage/tree?projectId={w.Tree.ProjectId}");

        Assert.True(r.GetProperty("measured").GetBoolean());
        Assert.Equal(200, r.GetProperty("totalSequences").GetInt32());
        Assert.Equal(80, r.GetProperty("coveredSequences").GetInt32());
        Assert.Equal(40.0, r.GetProperty("sequenceCoverage").GetDouble(), 3);
        Assert.Equal(50.0, r.GetProperty("branchCoverage").GetDouble(), 3);   // 10 / 20 (linux has no branches)
        var modules = r.GetProperty("modules").EnumerateArray().ToList();
        Assert.Equal(2, modules.Count);      // Core+core folded, Empty; the superseded build's module is excluded
        var core = modules.Single(m => string.Equals(m.GetProperty("name").GetString(), "core", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(70, core.GetProperty("coveredSequences").GetInt32());
        Assert.Equal(180, core.GetProperty("totalSequences").GetInt32());
        Assert.Equal(0.0, core.GetProperty("branchCoverage").GetDouble());
        var classes = core.GetProperty("classes").EnumerateArray().ToList();
        Assert.Equal(["Ns.Bar", "Ns.Foo"], classes.Select(c => c.GetProperty("fullName").GetString()!).ToArray());
        var foo = classes[1];
        Assert.Equal(50, foo.GetProperty("coveredSequences").GetInt32());      // 30 + 20 across the two reports
        Assert.Equal(140, foo.GetProperty("totalSequences").GetInt32());
        Assert.Equal("src/Core/Foo.cs", foo.GetProperty("sourceFileRelativePath").GetString());
        var empty = modules.Single(m => m.GetProperty("name").GetString() == "Empty");
        Assert.Equal(0.0, empty.GetProperty("sequenceCoverage").GetDouble());
        Assert.Equal(0.0, empty.GetProperty("classes")[0].GetProperty("sequenceCoverage").GetDouble());

        var byClient = await GetJsonAsync(http, $"/coverage/tree?clientId={w.Tree.ClientId}");
        Assert.True(byClient.GetProperty("measured").GetBoolean());
    }

    [SkippableFact]
    public async Task Coverage_tree_is_unmeasured_for_an_empty_scope_and_class_detail_404s_when_missing()
    {
        Skip.IfNot(_fx.Available);
        var admin = await UserAsync(_fx, admin: true);
        var empty = await ClientProjectAsync(_fx);
        var http = Http(_fx, admin);

        var r = await GetJsonAsync(http, $"/coverage/tree?projectId={empty.ProjectId}");
        Assert.False(r.GetProperty("measured").GetBoolean());
        Assert.Equal(JsonValueKind.Null, r.GetProperty("sequenceCoverage").ValueKind);
        Assert.Equal(0, r.GetProperty("modules").GetArrayLength());

        Assert.Equal(HttpStatusCode.NotFound, (await http.GetAsync($"/coverage/class/{Guid.NewGuid()}")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Http(_fx, null).GetAsync("/coverage/tree")).StatusCode);
    }

    [SkippableFact]
    public async Task Coverage_class_detail_returns_source_and_line_maps()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedCoverageAsync();
        var http = Http(_fx, w.Admin);

        var d = await GetJsonAsync(http, $"/coverage/class/{w.ClassCore}");

        Assert.Equal("Core", d.GetProperty("moduleName").GetString());
        Assert.Equal("Ns.Foo", d.GetProperty("fullName").GetString());
        Assert.Equal("src/Core/Foo.cs", d.GetProperty("sourceFileRelativePath").GetString());
        Assert.Equal(30, d.GetProperty("coveredSequences").GetInt32());
        Assert.Equal(40, d.GetProperty("totalSequences").GetInt32());
        Assert.Equal(3, d.GetProperty("coveredBranches").GetInt32());
        Assert.Equal("// foo\nclass Foo {}\n", d.GetProperty("sourceText").GetString());
        Assert.Equal([1, 2], d.GetProperty("visitedLines").EnumerateArray().Select(x => x.GetInt32()).ToArray());
        Assert.Equal([3], d.GetProperty("unvisitedLines").EnumerateArray().Select(x => x.GetInt32()).ToArray());

        // A class on a superseded build is still fetchable by id.
        var old = await GetJsonAsync(http, $"/coverage/class/{w.ClassOld}");
        Assert.Equal("Ns.Old", old.GetProperty("fullName").GetString());
    }
}
