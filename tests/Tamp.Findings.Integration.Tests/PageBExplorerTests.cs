using System.Net;
using Tamp.Findings.Domain.Values;
using Tamp.Findings.Web.Routing;

namespace Tamp.Findings.Integration.Tests;

[Collection(DatabaseCollection.Name)]
public sealed class PageBExplorerTests(DatabaseFixture fx)
{
    private readonly DatabaseFixture _fx = fx;

    private static string Route(string url)
    {
        var (path, p) = DastRoute.Normalize(url);
        return DastRoute.Display(path, p);
    }

    private static string[] Selections(string spine, PageBWorld w) => spine switch
    {
        "sast" => [PageBWorld.FileA, PageBWorld.FileB, PageBWorld.FileC, "no/such/file.cs"],
        "dast" => [Route("https://app.example.test/api/users?id=1"), Route("https://app.example.test/search?q=x"), "missing-route"],
        "a11y" => [Route("https://app.example.test/login"), Route("https://app.example.test/signup")],
        "sbom" => ["pkg:nuget/log4net@2.0.8", "pkg:nuget/Deep.Transitive@1.0.0", "pkg:nuget/Newtonsoft.Json@12.0.1", "pkg:nuget/Fresh.Lib@5.0.0"],
        "coverage" => [PageBWorld.FileA, PageBWorld.FileB, "src/Core/Calc.cs", "none.cs"],
        "tests" => ["Acme.Api.Tests.UserTests", "Acme.Core.Tests.CalcTests", "Nope.Tests"],
        _ => [],
    };

    [SkippableFact]
    public async Task Every_spine_renders_its_tree_and_each_selection()
    {
        Skip.IfNot(_fx.Available, "TAMP_FINDINGS_TEST_DB not set");
        var w = await PageBWorld.GetAsync(_fx);
        foreach (var spine in Spines.All)
        foreach (var sha in new[] { w.ShaNew, "latest" })
        {
            var (status, body) = await w.GetAsync(w.Build(sha, spine));
            Assert.True(status == HttpStatusCode.OK, $"{spine}/{sha}: {status}");
            Assert.DoesNotContain("Could not load this evidence", body);

            foreach (var sel in Selections(spine, w))
            {
                var (s, b) = await w.GetAsync(w.Build(sha, spine + "/" + sel));
                Assert.True(s == HttpStatusCode.OK, $"{spine}/{sel}: {s}");
                Assert.DoesNotContain("Could not load this evidence", b);
            }
        }
    }

    [SkippableFact]
    public async Task Sast_selection_shows_findings_and_source()
    {
        Skip.IfNot(_fx.Available, "TAMP_FINDINGS_TEST_DB not set");
        var w = await PageBWorld.GetAsync(_fx);
        var (_, body) = await w.GetAsync(w.Build("latest", "sast/" + PageBWorld.FileA));
        Assert.Contains("SQL injection in user lookup", body);
        Assert.Contains("Hard-coded credential", body);
        Assert.Contains("UserController", body);   // source viewer, from the coverage report's stored text

        var (_, cov) = await w.GetAsync(w.Build("latest", "coverage/" + PageBWorld.FileA));
        Assert.Contains("executable", cov);
    }

    [SkippableFact]
    public async Task Rule_grouping_renders_rule_breakdown_and_detail()
    {
        Skip.IfNot(_fx.Available, "TAMP_FINDINGS_TEST_DB not set");
        var w = await PageBWorld.GetAsync(_fx);
        foreach (var spine in new[] { "sast", "dast" })
        {
            var (s, b) = await w.GetAsync(w.Build("latest", spine) + "?group=rule");
            Assert.Equal(HttpStatusCode.OK, s);
            Assert.DoesNotContain("Could not load this evidence", b);
        }
        foreach (var rule in new[] { "csharp.sql-injection", "S2068", "no-eval", "nothing" })
        {
            var (s, b) = await w.GetAsync(w.Build("latest", "sast/" + rule) + "?group=rule");
            Assert.Equal(HttpStatusCode.OK, s);
            Assert.DoesNotContain("Could not load this evidence", b);
        }
        var (_, sql) = await w.GetAsync(w.Build("latest", "sast/csharp.sql-injection") + "?group=rule");
        Assert.Contains("SQL injection in user lookup", sql);
        foreach (var rule in new[] { "10202", "40012" })
        {
            var (s, _) = await w.GetAsync(w.Build("latest", "dast/" + rule) + "?group=rule");
            Assert.Equal(HttpStatusCode.OK, s);
        }
    }

    [SkippableFact]
    public async Task Explorer_handles_empty_unknown_and_hidden()
    {
        Skip.IfNot(_fx.Available, "TAMP_FINDINGS_TEST_DB not set");
        var w = await PageBWorld.GetAsync(_fx);
        foreach (var spine in Spines.All)
        {
            var (s, b) = await w.GetAsync($"/c/{w.Client}/p/{w.Empty}/build/{w.EmptySha}/{spine}");
            Assert.Equal(HttpStatusCode.OK, s);
            Assert.Contains("No ", b);
            var (s2, _) = await w.GetAsync($"/c/{w.Client}/p/{w.Empty}/build/latest/{spine}/anything?group=rule");
            Assert.Equal(HttpStatusCode.OK, s2);
        }

        var (_, unknown) = await w.GetAsync(w.Build("latest", "bogus"));
        Assert.Contains("Unknown spine", unknown);

        var (_, missing) = await w.GetAsync($"/c/{w.Client}/p/nope{w.Tag}/build/latest/sast");
        Assert.Contains("Project not found", missing);

        foreach (var who in new[] { PageBWorld.Viewer, PageBWorld.Lead })
        foreach (var spine in Spines.All)
        {
            var (s, _) = await w.GetAsync(w.Build("latest", spine), who);
            Assert.Equal(HttpStatusCode.OK, s);
        }
    }
}
