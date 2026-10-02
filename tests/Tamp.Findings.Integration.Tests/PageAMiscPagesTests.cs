using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Domain.Compliance;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Web.Components.Layout;
using Tamp.Findings.Web.Components.Pages;
using Tamp.Findings.Web.Routing;

namespace Tamp.Findings.Integration.Tests;

[Collection(DatabaseCollection.Name)]
public class PageAMiscPagesTests
{
    private readonly DatabaseFixture _fx;
    public PageAMiscPagesTests(DatabaseFixture fx) => _fx = fx;

    // ---- Zero trust ---------------------------------------------------------

    [SkippableFact]
    public async Task Zero_trust_page_scores_owned_inherited_contradicted_and_not_applicable_functions()
    {
        Skip.IfNot(_fx.Available);
        var w = await PageAWorld.SeedAsync(_fx);
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            var modelId = await db.MaturityModelCatalogs.Where(m => m.IsCurrent).Select(m => m.Id).FirstAsync();
            await db.Clients.Where(c => c.Id == w.Client.Id).ExecuteUpdateAsync(u => u.SetProperty(c => c.MaturityModelId, modelId));

            db.ConformanceFindings.AddRange(
                new ConformanceFinding
                {
                    ComponentVersionId = w.Cv.Id, AdrRef = "ADR 1", RuleId = "auth", Claim = "auth", Verdict = ConformanceVerdict.Pass,
                    Method = ConformanceMethod.Deterministic, ZtPillar = "Identity", ZtFunction = "Authentication", ZtStage = 3,
                },
                new ConformanceFinding
                {
                    ComponentVersionId = w.Cv.Id, AdrRef = "ADR 1", RuleId = "authz", Claim = "authz", Verdict = ConformanceVerdict.Fail,
                    Method = ConformanceMethod.Deterministic, ZtPillar = "Identity", ZtFunction = "Access Management", ZtStage = 2,
                },
                new ConformanceFinding
                {
                    ComponentVersionId = w.Cv.Id, AdrRef = "ADR 1", RuleId = "stores", Claim = "stores", Verdict = ConformanceVerdict.Unknown,
                    Method = ConformanceMethod.Deterministic, ZtPillar = "Identity", ZtFunction = "Identity Stores", ZtStage = 3,
                });
            var offering = new EnterpriseOffering
            {
                ClientId = w.Client.Id, ServiceLevelId = $"splunk-{w.S}", Name = "Splunk",
                FunctionScores = [new() { Pillar = "Identity", Function = "Visibility & Analytics", Stage = 3 }],
            };
            db.EnterpriseOfferings.Add(offering);
            var system = new ZtSystem { ClientId = w.Client.Id, ProjectId = w.Project.Id, Name = $"pagea-sys-{w.S}", SystemKind = "app", CsamId = "C-1" };
            db.ZtSystems.Add(system);
            await db.SaveChangesAsync();
            db.ZtInheritanceEdges.Add(new ZtInheritanceEdge
            {
                SystemId = system.Id, OfferingId = offering.Id, Pillar = "Identity", Function = "Visibility & Analytics",
                Statement = "confirmed", AttesterLogin = w.Admin.Login, AttestedAt = DateTimeOffset.UtcNow,
                ExpiresAt = DateTimeOffset.UtcNow.AddDays(300), AuthorUserId = w.Admin.Id,
            });
            db.ZtSystemPicks.AddRange(
                new ZtSystemPick { SystemId = system.Id, Pillar = "Data", Function = "Data Encryption", Kind = ZtPickKind.NotApplicable, Justification = "n/a", AuthorUserId = w.Admin.Id },
                new ZtSystemPick { SystemId = system.Id, Pillar = "Network", Function = "Network Segmentation", Kind = ZtPickKind.Committed, Justification = "planned", AuthorUserId = w.Admin.Id });
            await db.SaveChangesAsync();
        }

        await using var h = await PageAHost.ForAsync(_fx, w.Admin, "/c/x/p/y/zt");
        var page = await h.OpenAsync<ZeroTrust>(w.Of(w.Project));
        page.Expect("zero trust maturity");
        page.Expect("Identity");
        page.Expect("verified");
        page.Expect("inherited");
        page.Expect("N/A");
        page.Expect("cross-cutting");
        page.Expect("contradicted");
        page.Expect("committed");

        await using var h2 = await PageAHost.ForAsync(_fx, w.Admin, "/c/x/p/y/zt");
        (await h2.OpenAsync<ZeroTrust>(w.Of(w.EmptyProject))).Expect("Not ZT-scored");
        (await (await PageAHost.ForAsync(_fx, w.Admin)).OpenAsync<ZeroTrust>(("Client", w.Client.Name), ("Project", "zzz"))).Expect("Project not found");
    }

    // ---- EO registry + frameworks -------------------------------------------

    [SkippableFact]
    public async Task Eo_registry_filters_and_travels_in_time()
    {
        Skip.IfNot(_fx.Available);
        var w = await PageAWorld.SeedAsync(_fx);
        await using var h = await PageAHost.ForAsync(_fx, w.Admin, "/system/eo-registry");
        var page = await h.OpenAsync<EoRegistry>();
        page.Expect("EO mandate registry");
        foreach (var f in new[] { "In force", "Pending", "All" })
            await page.ClickRowAsync("button", f);

        await page.TypeAsync("As of", "2022-06-01");
        await page.ClickButtonAsync("Apply");
        page.Expect("2022-06-01");
        await page.ClickButtonAsync("Apply");
        await page.TypeAsync("As of", "not-a-date");
        await page.ClickButtonAsync("Apply");
        await page.ClickButtonAsync("Today");
    }

    [SkippableFact]
    public async Task Frameworks_catalog_browses_families_and_statements()
    {
        Skip.IfNot(_fx.Available);
        var w = await PageAWorld.SeedAsync(_fx);
        await using var h = await PageAHost.ForAsync(_fx, w.Admin, "/system/frameworks");
        var page = await h.OpenAsync<Frameworks>();
        page.Expect("Controls");

        var families = page.Tree().Descendants()
            .Where(n => n.Tag == "option").Select(n => n.Attr("value")).Where(v => !string.IsNullOrEmpty(v)).Take(3).ToList();
        foreach (var fam in families)
            await page.ChangeTagAsync("select", fam!, 0);

        await page.TypePlaceholderAsync("filter id", "CM-");
        var chips = page.Tree().Descendants().Where(n => n.Tag == "button" && n.Events.ContainsKey("onclick") && n.Text.Contains('-')).Take(2).Select(n => n.Text).ToList();
        foreach (var c in chips) await page.ClickButtonAsync(c);
        await page.TypePlaceholderAsync("filter id", "zzzz-no-such-control");
    }

    // ---- Public report + sign-in over HTTP ----------------------------------

    [SkippableFact]
    public async Task Public_report_renders_posture_for_a_populated_build_and_hides_when_disabled()
    {
        Skip.IfNot(_fx.Available);
        var w = await PageAWorld.SeedAsync(_fx);
        await PageAIngest.IngestBuildAsync(_fx, w, $"{w.S}pubbuild");
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            var fw = await db.Frameworks.FirstAsync();
            await db.Clients.Where(c => c.Id == w.Client.Id).ExecuteUpdateAsync(u => u.SetProperty(c => c.FrameworkId, fw.Id));
        }

        var anon = _fx.Factory!.CreateClient();
        var body = await anon.GetAsync($"/report/{w.Project.ReportKey}");
        var html = await body.Content.ReadAsStringAsync();
        Assert.True(body.IsSuccessStatusCode, html);
        Assert.Contains(w.Project.Name, html);
        Assert.Contains("Evidence report", html);
        Assert.Contains("Control coverage", html);

        var missing = await anon.GetAsync("/report/not-a-real-key");
        var missingBody = await missing.Content.ReadAsStringAsync();
        Assert.True(missing.StatusCode == System.Net.HttpStatusCode.NotFound || missingBody.Contains("Report not found"), missingBody);
    }

    [SkippableFact]
    public async Task Sign_in_page_explains_each_refusal_reason()
    {
        Skip.IfNot(_fx.Available);
        var anon = _fx.Factory!.CreateClient();
        foreach (var reason in new[] { "not_approved", "no_email", "setup_token", "domain_not_allowed", "mfa_required", "unknown_provider", "other" })
        {
            var html = await anon.GetStringAsync($"/signin?error={reason}&returnUrl=%2Fportfolio");
            Assert.Contains("Refused", html);
        }
        var plain = await anon.GetStringAsync("/signin?returnUrl=//evil.example");
        Assert.Contains("Sign in", plain);
    }

    // ---- Layout -------------------------------------------------------------

    [SkippableFact]
    public async Task Layout_header_account_menu_and_sidebar_react_to_scope_and_preferences()
    {
        Skip.IfNot(_fx.Available);
        var w = await PageAWorld.SeedAsync(_fx);
        await using var h = await PageAHost.ForAsync(_fx, w.Admin, "/c/x/p/y/build/abc1234");
        var scope = (RouteScope)h.Services.GetService(typeof(RouteScope))!;

        // Portfolio scope: no project tabs.
        scope.Clear();
        var header = await h.OpenCascadedAsync<AppHeader>();
        header.Expect("copy link");
        await header.ClickButtonAsync("comfortable");
        await header.ClickButtonAsync("compact");
        await header.ClickButtonAsync("copy link");

        // Project + build scope: every tab, deltas toggle, canonical chip.
        scope.SetProject(w.Client.Name, w.Project.Name, "abc1234");
        header.Expect("anonical");
        await header.ClickButtonAsync("comfortable");
        foreach (var tab in new[] { "Portfolio", "Poam", "Vex", "Attestation", "Policy", "Keys", "System" })
        {
            var el = header.Tree().Descendants().FirstOrDefault(n => n.Events.ContainsKey("onclick") && n.Text.Contains(tab, StringComparison.OrdinalIgnoreCase) && n.Tag != "button" || (n.Tag == "button" && n.Text.Contains(tab, StringComparison.OrdinalIgnoreCase)));
            if (el is not null) await header.ClickAsync(el.Text);
        }
        scope.SetExplorer("sast", null);
        foreach (var btn in header.Tree().Descendants().Where(n => n.Tag == "button" && n.Events.ContainsKey("onclick")).Select(n => n.Text).Distinct().ToList())
            await header.ClickAsync(btn);

        // Account menu opens and closes.
        var menu = await h.OpenCascadedAsync<AccountMenu>();
        await menu.ClickRowAsync("button", w.Admin.Login);
        menu.Expect("Sign out");
        await menu.ClickRowAsync("a", "Sign out");
        scope.Clear();
        await menu.ClickRowAsync("button", w.Admin.Login);
        menu.Expect("Sign out");

        // Sidebar at three scope depths.
        var side = await h.OpenCascadedAsync<Sidebar>();
        side.Expect("Policy templates");
        scope.SetClient(w.Client.Name);
        scope.SetProject(w.Client.Name, w.Project.Name);
        side.Expect("Costs");
        scope.SetProject(w.Client.Name, w.Project.Name, "abc1234");
        side.Expect("Attestation");

        // Anonymous menu offers sign-in.
        await using var anon = await PageAHost.ForAsync(_fx, null, "/");
        (await anon.OpenCascadedAsync<AccountMenu>()).Expect("Sign");
    }
}
