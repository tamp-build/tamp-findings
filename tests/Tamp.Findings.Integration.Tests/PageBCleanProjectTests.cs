using System.Net;
using Tamp.Findings.Web.Routing;
using CategoryPage = Tamp.Findings.Web.Components.Pages.CategoryDetail;
using EvidencePage = Tamp.Findings.Web.Components.Pages.EvidenceDetail;
using ExplorerPage = Tamp.Findings.Web.Components.Pages.Explorer;
using HubPage = Tamp.Findings.Web.Components.Pages.ProjectHub;

namespace Tamp.Findings.Integration.Tests;

/// <summary>
/// A project where everything ran and everything passed: the "scanned, clean" branches of every page,
/// which a findings-heavy project never reaches.
/// </summary>
[Collection(DatabaseCollection.Name)]
public sealed class PageBCleanProjectTests(DatabaseFixture fx)
{
    private readonly DatabaseFixture _fx = fx;

    [SkippableFact]
    public async Task Clean_project_says_clean_with_evidence_on_every_category()
    {
        Skip.IfNot(_fx.Available, "TAMP_FINDINGS_TEST_DB not set");
        var w = await PageBWorld.GetAsync(_fx);
        var (name, _, sha) = await w.NewCleanProjectAsync("clean");

        var (_, cve) = await w.GetAsync($"/c/{w.Client}/p/{name}/build/{sha}/score/cve");
        Assert.Contains("Scanned", cve);
        Assert.Contains("No known CVEs", cve);

        var (_, tests) = await w.GetAsync($"/c/{w.Client}/p/{name}/build/{sha}/score/tests");
        Assert.Contains("Clean.Tests", tests);

        var (_, fresh) = await w.GetAsync($"/c/{w.Client}/p/{name}/build/{sha}/score/sbomStaleness");
        Assert.Contains("Every non-vulnerable component is on its newest version", fresh);

        foreach (var key in PageBCategoryTests.Keys)
        {
            var (s, b) = await w.GetAsync($"/c/{w.Client}/p/{name}/build/{sha}/score/{key}");
            Assert.Equal(HttpStatusCode.OK, s);
            Assert.Contains($">{key}<", b);
            await using var page = await PageBRenderHost.RenderAsync<CategoryPage>(w,
                new Dictionary<string, object?> { ["Client"] = w.Client, ["Project"] = name, ["Sha"] = sha, ["Key"] = key });
            Assert.Empty(page.Errors);
        }
    }

    [SkippableFact]
    public async Task Clean_project_evidence_explorer_hub_and_attestation_render()
    {
        Skip.IfNot(_fx.Available, "TAMP_FINDINGS_TEST_DB not set");
        var w = await PageBWorld.GetAsync(_fx);
        var (name, _, sha) = await w.NewCleanProjectAsync("cleane");
        var root = $"/c/{w.Client}/p/{name}/build/{sha}";

        foreach (var key in EvidenceKeys.All)
        {
            var (s, b) = await w.GetAsync($"{root}/evidence/{key}");
            Assert.Equal(HttpStatusCode.OK, s);
            Assert.Contains($">{key}<", b);
            await using var page = await PageBRenderHost.RenderAsync<EvidencePage>(w,
                new Dictionary<string, object?> { ["Client"] = w.Client, ["Project"] = name, ["Sha"] = sha, ["Key"] = key });
            Assert.Empty(page.Errors);
        }
        foreach (var spine in Spines.All)
        {
            var (s, _) = await w.GetAsync($"{root}/{spine}");
            Assert.Equal(HttpStatusCode.OK, s);
            await using var page = await PageBRenderHost.RenderAsync<ExplorerPage>(w,
                new Dictionary<string, object?> { ["Client"] = w.Client, ["Project"] = name, ["Sha"] = sha, ["Spine"] = spine, ["Selection"] = null });
            Assert.Empty(page.Errors);
        }
        var (_, cov) = await w.GetAsync($"{root}/coverage/src/Clean/Thing.cs");
        Assert.Contains("Thing", cov);

        var (sh, hub) = await w.GetAsync(root);
        Assert.Equal(HttpStatusCode.OK, sh);
        Assert.Contains(name, hub);
        await using var hubPage = await PageBRenderHost.RenderAsync<HubPage>(w,
            new Dictionary<string, object?> { ["Client"] = w.Client, ["Project"] = name, ["Sha"] = sha });
        Assert.Empty(hubPage.Errors);

        var (sa, _) = await w.GetAsync($"{root}/attestation");
        Assert.Equal(HttpStatusCode.OK, sa);
    }
}
