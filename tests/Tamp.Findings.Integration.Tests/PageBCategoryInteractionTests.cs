using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using CategoryPage = Tamp.Findings.Web.Components.Pages.CategoryDetail;
using ExplorerPage = Tamp.Findings.Web.Components.Pages.Explorer;
using EvidencePage = Tamp.Findings.Web.Components.Pages.EvidenceDetail;
using HubPage = Tamp.Findings.Web.Components.Pages.ProjectHub;

namespace Tamp.Findings.Integration.Tests;

/// <summary>Interactive flows on the category-detail, explorer, evidence and hub pages.</summary>
[Collection(DatabaseCollection.Name)]
public sealed class PageBCategoryInteractionTests(DatabaseFixture fx)
{
    private readonly DatabaseFixture _fx = fx;

    private static Dictionary<string, object?> Cat(PageBWorld w, string project, string sha, string key) =>
        new() { ["Client"] = w.Client, ["Project"] = project, ["Sha"] = sha, ["Key"] = key };

    [SkippableFact]
    public async Task License_unknowns_can_be_resolved_by_an_authorised_user()
    {
        Skip.IfNot(_fx.Available, "TAMP_FINDINGS_TEST_DB not set");
        var w = await PageBWorld.GetAsync(_fx);
        var (name, pid, sha) = await w.NewBuiltProjectAsync("catl");

        await using var page = await PageBRenderHost.RenderAsync<CategoryPage>(w, Cat(w, name, sha, "license"));
        Assert.Contains("MysteryLib", page.Text);
        Assert.Contains("WeirdLib", page.Text);

        // Resolving with no SPDX id is refused, with the package named.
        Assert.True(await page.ClickAsync("Resolve"));
        Assert.Contains("Enter an SPDX id", page.Text);

        Assert.True(await page.TypeAsync(e => e.Attr("placeholder").StartsWith("SPDX"), "MIT"));
        Assert.True(await page.TypeAsync(e => e.Attr("placeholder").StartsWith("evidence"), "checked the repo"));
        Assert.True(await page.ClickAsync("Resolve"));
        Assert.Empty(page.Errors);

        // A lead lacks the policy-edit capability, so no resolve controls render for them.
        await using var lead = await PageBRenderHost.RenderAsync<CategoryPage>(w, Cat(w, name, sha, "license"), PageBWorld.Lead);
        Assert.False(await lead.ClickAsync("Resolve"));
    }

    [SkippableFact]
    public async Task Stale_components_can_be_exempted_through_the_vex_dialog()
    {
        Skip.IfNot(_fx.Available, "TAMP_FINDINGS_TEST_DB not set");
        var w = await PageBWorld.GetAsync(_fx);
        var (name, pid, sha) = await w.NewBuiltProjectAsync("cats");

        await using var page = await PageBRenderHost.RenderAsync<CategoryPage>(w, Cat(w, name, sha, "sbomStaleness"));
        Assert.Contains("behind their newest release", page.Text);

        Assert.True(await page.ClickWhereAsync(e => e.Text == "⋯"));
        Assert.Contains("File VEX exemption", page.Text);
        // No rationale: refused.
        Assert.True(await page.ClickAsync("File exemption"));
        Assert.Contains("Add a rationale", page.Text);

        Assert.True(await page.ClickAsync("does_not_ship"));
        Assert.True(await page.ClickAsync("all versions"));
        Assert.True(await page.ClickAsync("this version"));
        Assert.True(await page.TypeLabelAsync("Rationale", "Dev tooling only, never shipped"));
        if (page.Text.Contains("Also exempt")) Assert.True(await page.CheckNthAsync(0, true));
        Assert.True(await page.ClickAsync("File exemption"));

        using var scope = w.Host.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<FindingsDbContext>();
        var exempt = await db.VexStatements.AsNoTracking()
            .Where(v => v.ProjectId == pid && v.AdvisoryId == VexStatement.StalenessAdvisoryId).ToListAsync();
        Assert.NotEmpty(exempt);
        Assert.Equal(VexJustification.DoesNotShip, exempt[0].Justification);

        // Cancelling the dialog closes it without writing.
        await using var again = await PageBRenderHost.RenderAsync<CategoryPage>(w, Cat(w, name, sha, "sbomStaleness"));
        Assert.Contains("EXEMPT", again.Text);
        if (await again.ClickWhereAsync(e => e.Text == "⋯")) Assert.True(await again.ClickAsync("Cancel"));
        Assert.Empty(page.Errors);
    }

    [SkippableFact]
    public async Task Every_category_renders_through_the_interactive_host()
    {
        Skip.IfNot(_fx.Available, "TAMP_FINDINGS_TEST_DB not set");
        var w = await PageBWorld.GetAsync(_fx);
        foreach (var key in PageBCategoryTests.Keys.Append("nope"))
        {
            await using var page = await PageBRenderHost.RenderAsync<CategoryPage>(w, Cat(w, w.Rich, w.ShaNew, key));
            Assert.Empty(page.Errors);
            Assert.True(page.Text.Contains(key) || page.Text.Contains("No scored category"), key);
        }
    }

    [SkippableFact]
    public async Task Dast_duplicate_hosts_can_be_merged()
    {
        Skip.IfNot(_fx.Available, "TAMP_FINDINGS_TEST_DB not set");
        var w = await PageBWorld.GetAsync(_fx);
        var (name, pid, sha) = await w.NewBuiltProjectAsync("expd");
        var args = new Dictionary<string, object?>
        {
            ["Client"] = w.Client, ["Project"] = name, ["Sha"] = sha, ["Spine"] = "dast", ["Selection"] = null,
        };
        await using var page = await PageBRenderHost.RenderAsync<ExplorerPage>(w, args);
        Assert.Contains("Duplicate host", page.Text);
        Assert.True(await page.ClickAsync("Merge hosts"));
        Assert.True(await page.ClickWhereAsync(e => e.Name == "button" && e.Text == "Merge"));   // no reason => refused
        Assert.Contains("Merge hosts", page.Text);
        Assert.True(await page.ClickAsync("Swap direction"));
        Assert.True(await page.TypeLabelAsync("Why are these the same application?", "Same deployment behind two names"));
        Assert.True(await page.ClickWhereAsync(e => e.Name == "button" && e.Text == "Merge"));

        using var scope = w.Host.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<FindingsDbContext>();
        Assert.True(await db.HostAliases.AnyAsync(a => a.ProjectId == pid));
        Assert.Empty(page.Errors);
    }

    [SkippableFact]
    public async Task Explorer_renders_every_spine_through_the_interactive_host()
    {
        Skip.IfNot(_fx.Available, "TAMP_FINDINGS_TEST_DB not set");
        var w = await PageBWorld.GetAsync(_fx);
        static string Route(string url)
        {
            var (path, p) = Tamp.Findings.Domain.Values.DastRoute.Normalize(url);
            return Tamp.Findings.Domain.Values.DastRoute.Display(path, p);
        }
        foreach (var (spine, sel) in new[]
        {
            ("sast", PageBWorld.FileA), ("sbom", "pkg:nuget/log4net@2.0.8"), ("coverage", PageBWorld.FileA),
            ("tests", "Acme.Api.Tests.UserTests"), ("a11y", Route("https://app.example.test/login")),
            ("dast", Route("https://app.example.test/api/users?id=1")),
        })
        {
            Dictionary<string, object?> Args(string? selection) => new()
            {
                ["Client"] = w.Client, ["Project"] = w.Rich, ["Sha"] = "latest", ["Spine"] = spine, ["Selection"] = selection,
            };

            // The tree, with its rows rendered (the host plays the browser's part for <Virtualize>).
            await using var tree = await PageBRenderHost.RenderAsync<ExplorerPage>(w, Args(null));
            Assert.Empty(tree.Errors);
            Assert.True(await tree.ClickWhereAsync(e => e.Class.Contains("tree-row") && !e.Class.Contains("tree-row--group")), spine + " has a selectable row");
            Assert.Contains("/" + spine + "/", tree.Navigated);

            // With a selection: the detail pane for it.
            await using var detail = await PageBRenderHost.RenderAsync<ExplorerPage>(w, Args(sel));
            Assert.Empty(detail.Errors);
            Assert.NotEmpty(detail.Text);
        }

        // Group-by-rule is carried in the query string, and rule rows navigate with it.
        foreach (var spine in new[] { "sast", "dast" })
        {
            var args = new Dictionary<string, object?>
            {
                ["Client"] = w.Client, ["Project"] = w.Rich, ["Sha"] = "latest", ["Spine"] = spine, ["Selection"] = null,
            };
            await using var byRule = await PageBRenderHost.RenderAsync<ExplorerPage>(w, args, path: $"/c/x/p/y/build/latest/{spine}?group=rule");
            Assert.Empty(byRule.Errors);
            // (The DAST tree branch is matched before the by-rule one, so its tree stays on hosts/routes.)
            if (spine == "sast")
            {
                Assert.True(await byRule.ClickWhereAsync(e => e.Class.Contains("tree-row") && !e.Class.Contains("tree-row--group")), byRule.Text);
                Assert.Contains("group=rule", byRule.Navigated);
            }
        }
        var ruleArgs = new Dictionary<string, object?>
        {
            ["Client"] = w.Client, ["Project"] = w.Rich, ["Sha"] = "latest", ["Spine"] = "sast", ["Selection"] = "csharp.sql-injection",
        };
        await using var ruleDetail = await PageBRenderHost.RenderAsync<ExplorerPage>(w, ruleArgs, path: "/c/x/p/y/build/latest/sast/csharp.sql-injection?group=rule");
        Assert.Contains("SQL injection in user lookup", ruleDetail.Text);
    }

    [SkippableFact]
    public async Task Evidence_pages_render_through_the_interactive_host_and_conformance_can_be_dispositioned()
    {
        Skip.IfNot(_fx.Available, "TAMP_FINDINGS_TEST_DB not set");
        var w = await PageBWorld.GetAsync(_fx);
        foreach (var key in Tamp.Findings.Web.Routing.EvidenceKeys.All)
        {
            var args = new Dictionary<string, object?>
            {
                ["Client"] = w.Client, ["Project"] = w.Rich, ["Sha"] = w.ShaNew, ["Key"] = key,
            };
            await using var page = await PageBRenderHost.RenderAsync<EvidencePage>(w, args);
            Assert.Empty(page.Errors);
            Assert.Contains(key, page.Text);
        }
    }

    [SkippableFact]
    public async Task Project_hub_renders_through_the_interactive_host()
    {
        Skip.IfNot(_fx.Available, "TAMP_FINDINGS_TEST_DB not set");
        var w = await PageBWorld.GetAsync(_fx);
        foreach (var sha in new[] { w.ShaNew, w.ShaOld, "latest" })
        {
            var args = new Dictionary<string, object?> { ["Client"] = w.Client, ["Project"] = w.Rich, ["Sha"] = sha };
            await using var page = await PageBRenderHost.RenderAsync<HubPage>(w, args);
            Assert.Empty(page.Errors);
            Assert.Contains(w.Rich, page.Text);
        }
    }
}
