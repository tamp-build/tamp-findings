using System.Net;

namespace Tamp.Findings.Integration.Tests;

[Collection(DatabaseCollection.Name)]
public sealed class PageBProjectPagesTests(DatabaseFixture fx)
{
    private readonly DatabaseFixture _fx = fx;

    private string Proj(PageBWorld w, string tail) => $"/c/{w.Client}/p/{w.Rich}/{tail}";

    [SkippableFact]
    public async Task Poam_board_and_every_item_render()
    {
        Skip.IfNot(_fx.Available, "TAMP_FINDINGS_TEST_DB not set");
        var w = await PageBWorld.GetAsync(_fx);
        var (s, board) = await w.GetAsync(Proj(w, "poam"));
        Assert.Equal(HttpStatusCode.OK, s);
        Assert.Contains("PastDue SQLi remediation", board);
        Assert.Contains("ZT contradiction", board);

        foreach (var id in w.PoamItemIds)
        {
            var (si, bi) = await w.GetAsync(Proj(w, "poam/" + id));
            Assert.Equal(HttpStatusCode.OK, si);
            Assert.Contains("weakness", bi);
        }

        var (_, unknownItem) = await w.GetAsync(Proj(w, "poam/" + Guid.NewGuid()));
        Assert.NotEmpty(unknownItem);
        var (_, badItem) = await w.GetAsync(Proj(w, "poam/not-a-guid"));
        Assert.NotEmpty(badItem);

        foreach (var who in new[] { PageBWorld.Lead, PageBWorld.Viewer })
        {
            var (sw, _) = await w.GetAsync(Proj(w, "poam"), who);
            Assert.Equal(HttpStatusCode.OK, sw);
            var (sd, _) = await w.GetAsync(Proj(w, "poam/" + w.PoamItemId), who);
            Assert.Equal(HttpStatusCode.OK, sd);
        }

        var (se, empty) = await w.GetAsync($"/c/{w.Client}/p/{w.Empty}/poam");
        Assert.Equal(HttpStatusCode.OK, se);
        Assert.NotEmpty(empty);
        var (sn, _) = await w.GetAsync($"/c/{w.Client}/p/{w.NoBuilds}/poam/" + w.PoamItemId);
        Assert.Equal(HttpStatusCode.OK, sn);
    }

    [SkippableFact]
    public async Task Vex_page_lists_statements_and_prefills_from_query()
    {
        Skip.IfNot(_fx.Available, "TAMP_FINDINGS_TEST_DB not set");
        var w = await PageBWorld.GetAsync(_fx);
        var (s, body) = await w.GetAsync(Proj(w, "vex"));
        Assert.Equal(HttpStatusCode.OK, s);
        Assert.Contains("GHSA-5crp-9r3c-p9vr", body);
        Assert.Contains("CVE-2018-1285", body);
        Assert.Contains("Newtonsoft.Json", body);

        var (_, prefilled) = await w.GetAsync(Proj(w, "vex") + "?purl=pkg%3Anuget%2Flog4net%402.0.8&advisory=CVE-2018-1285");
        Assert.Contains("CVE-2018-1285", prefilled);
        var (_, prefilled2) = await w.GetAsync(Proj(w, "vex") + "?purl=pkg%3Anuget%2Funknown%401&advisory=CVE-0000-0000");
        Assert.NotEmpty(prefilled2);

        foreach (var who in new[] { PageBWorld.Lead, PageBWorld.Viewer })
        {
            var (sw, _) = await w.GetAsync(Proj(w, "vex"), who);
            Assert.Equal(HttpStatusCode.OK, sw);
        }
        var (se, _) = await w.GetAsync($"/c/{w.Client}/p/{w.Empty}/vex");
        Assert.Equal(HttpStatusCode.OK, se);
        var (sm, _) = await w.GetAsync($"/c/{w.Client}/p/nope{w.Tag}/vex");
        Assert.Equal(HttpStatusCode.OK, sm);
    }

    [SkippableFact]
    public async Task Attestation_renders_for_builds_with_and_without_evidence()
    {
        Skip.IfNot(_fx.Available, "TAMP_FINDINGS_TEST_DB not set");
        var w = await PageBWorld.GetAsync(_fx);
        foreach (var sha in new[] { w.ShaNew, w.ShaMid, w.ShaOld, "latest" })
        {
            var (s, body) = await w.GetAsync(w.Build(sha, "attestation"));
            Assert.Equal(HttpStatusCode.OK, s);
            Assert.Contains("PS.", body);   // SSDF practice ids
        }
        foreach (var who in new[] { PageBWorld.Lead, PageBWorld.Viewer })
        {
            var (s, _) = await w.GetAsync(w.Build(w.ShaNew, "attestation"), who);
            Assert.Equal(HttpStatusCode.OK, s);
        }
        var (se, _) = await w.GetAsync($"/c/{w.Client}/p/{w.Empty}/build/{w.EmptySha}/attestation");
        Assert.Equal(HttpStatusCode.OK, se);
        var (sn, _) = await w.GetAsync($"/c/{w.Client}/p/{w.NoBuilds}/build/latest/attestation");
        Assert.Equal(HttpStatusCode.OK, sn);
        var (sx, _) = await w.GetAsync($"/c/{w.Client}/p/nope{w.Tag}/build/latest/attestation");
        Assert.Equal(HttpStatusCode.OK, sx);
    }

    [SkippableFact]
    public async Task Project_settings_every_tab_renders_for_each_role()
    {
        Skip.IfNot(_fx.Available, "TAMP_FINDINGS_TEST_DB not set");
        var w = await PageBWorld.GetAsync(_fx);
        foreach (var who in new[] { PageBWorld.Admin, PageBWorld.Lead, PageBWorld.Viewer })
        foreach (var tab in new[] { "keys", "archetype", "report", "agents", "disclosure", "account", "bogus" })
        {
            var (s, body) = await w.GetAsync(Proj(w, "settings/" + tab), who);
            Assert.True(s == HttpStatusCode.OK, $"{who}/{tab}: {s}");
            Assert.NotEmpty(body);
        }
        var (_, keys) = await w.GetAsync(Proj(w, "settings/keys"));
        Assert.Contains("ci-token", keys);
        var (_, agents) = await w.GetAsync(Proj(w, "settings/agents"));
        Assert.Contains("agent-live", agents);
        var (_, disclosure) = await w.GetAsync(Proj(w, "settings/disclosure"));
        Assert.Contains("https://example.test/security", disclosure);

        var (sd, _) = await w.GetAsync(Proj(w, "settings/keys"));
        Assert.Equal(HttpStatusCode.OK, sd);
        foreach (var tab in new[] { "keys", "report", "disclosure" })
        {
            var (s, _) = await w.GetAsync($"/c/{w.Client}/p/{w.Empty}/settings/{tab}");
            Assert.Equal(HttpStatusCode.OK, s);
        }
        var (sm, _) = await w.GetAsync($"/c/{w.Client}/p/nope{w.Tag}/settings/keys");
        Assert.Equal(HttpStatusCode.OK, sm);
    }

    [SkippableFact]
    public async Task Project_hub_renders_every_build_and_state()
    {
        Skip.IfNot(_fx.Available, "TAMP_FINDINGS_TEST_DB not set");
        var w = await PageBWorld.GetAsync(_fx);
        foreach (var sha in new[] { w.ShaNew, w.ShaMid, w.ShaOld, "latest" })
        {
            var (s, body) = await w.GetAsync(w.Build(sha));
            Assert.Equal(HttpStatusCode.OK, s);
            Assert.Contains(w.Rich, body);
        }
        var (_, hub) = await w.GetAsync(w.Build("latest"));
        Assert.Contains("ghcr.io/acme/app", hub);
        foreach (var who in new[] { PageBWorld.Lead, PageBWorld.Viewer })
        {
            var (s, _) = await w.GetAsync(w.Build("latest"), who);
            Assert.Equal(HttpStatusCode.OK, s);
        }
        var (se, _) = await w.GetAsync($"/c/{w.Client}/p/{w.Empty}/build/{w.EmptySha}");
        Assert.Equal(HttpStatusCode.OK, se);
        var (sn, _) = await w.GetAsync($"/c/{w.Client}/p/{w.NoBuilds}/build/latest");
        Assert.Equal(HttpStatusCode.OK, sn);
        var (sx, _) = await w.GetAsync($"/c/{w.Client}/p/{w.Rich}/build/deadbeef");
        Assert.Equal(HttpStatusCode.OK, sx);
    }

    [SkippableFact]
    public async Task Category_pages_for_empty_nobuild_hidden_and_unknown()
    {
        Skip.IfNot(_fx.Available, "TAMP_FINDINGS_TEST_DB not set");
        var w = await PageBWorld.GetAsync(_fx);
        foreach (var key in PageBCategoryTests.Keys.Append("bogusKey"))
        {
            foreach (var path in new[]
            {
                $"/c/{w.Client}/p/{w.Empty}/build/{w.EmptySha}/score/{key}",
                $"/c/{w.Client}/p/{w.Empty}/build/latest/score/{key}",
                $"/c/{w.Client}/p/{w.NoBuilds}/build/latest/score/{key}",
                $"/c/{w.Client}/p/nope{w.Tag}/build/latest/score/{key}",
            })
            {
                var (s, _) = await w.GetAsync(path);
                Assert.Equal(HttpStatusCode.OK, s);
            }
            foreach (var who in new[] { PageBWorld.Lead, PageBWorld.Viewer })
            {
                var (s, _) = await w.GetAsync(w.Build(w.ShaNew, "score/" + key), who);
                Assert.Equal(HttpStatusCode.OK, s);
            }
        }
        var (_, none) = await w.GetAsync(w.Build(w.ShaNew, "score/bogusKey"));
        Assert.Contains("No scored category", none);
    }
}
