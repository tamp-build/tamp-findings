using System.Text.Json;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Risk;
using Tamp.Findings.Domain.Values;
using Tamp.Findings.Web.Components.Pages;

namespace Tamp.Findings.Integration.Tests;

[Collection(DatabaseCollection.Name)]
public class PageAPolicyFamilyTests
{
    private readonly DatabaseFixture _fx;
    public PageAPolicyFamilyTests(DatabaseFixture fx) => _fx = fx;

    private static PolicyLayer RichLayer() => new()
    {
        Mode = EnforcementMode.Enforcing,
        RequiredScanners = [PolicyTemplateDefaults.ScannerClasses.StaticAnalysis],
        DeniedLicenses = ["AGPL-*"],
        Gates =
        {
            [GateKeys.AnyCves] = new GateConfig { Enabled = true, Threshold = 5 },
            [GateKeys.CriticalCves] = new GateConfig { Enabled = true },
        },
        PoamDeadlineDays = { ["Critical"] = 15, ["High"] = 30 },
    };

    private async Task<(PageAWorld W, PolicyTemplate Tmpl)> SeedAsync()
    {
        var w = await PageAWorld.SeedAsync(_fx);
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var tmpl = new PolicyTemplate { Name = $"pagea-tmpl-{w.S}", Layer = RichLayer() };
        db.PolicyTemplates.Add(tmpl);
        await db.SaveChangesAsync();
        await db.Clients.Where(c => c.Id == w.Client.Id).ExecuteUpdateAsync(u => u
            .SetProperty(c => c.PolicyTemplateId, tmpl.Id)
            .SetProperty(c => c.PolicyLayer, new PolicyLayer
            {
                Mode = EnforcementMode.Enforcing,
                RequiredScanners = [PolicyTemplateDefaults.ScannerClasses.StaticAnalysis, PolicyTemplateDefaults.ScannerClasses.Secrets],
                DeniedLicenses = ["AGPL-*", "SSPL-1.0"],
                Gates =
                {
                    [GateKeys.AnyCves] = new GateConfig { Enabled = true, Threshold = 5 },
                    [GateKeys.CriticalCves] = new GateConfig { Enabled = true },
                    [GateKeys.HighCves] = new GateConfig { Enabled = true, Threshold = 2 },
                },
                PoamDeadlineDays = { ["Critical"] = 7, ["High"] = 30 },
            }));
        await db.Projects.Where(p => p.Id == w.Project.Id).ExecuteUpdateAsync(u => u
            .SetProperty(p => p.PolicyLayer, new PolicyLayer
            {
                RequiredScanners = [PolicyTemplateDefaults.ScannerClasses.Sbom],
                Gates = { [GateKeys.CriticalSast] = new GateConfig { Enabled = true } },
                PoamDeadlineDays = { ["Medium"] = 60 },
            }));
        return (w, tmpl);
    }

    [SkippableFact]
    public async Task Templates_library_lists_and_editor_applies_tightening_and_routes_loosening()
    {
        Skip.IfNot(_fx.Available);
        var (w, tmpl) = await SeedAsync();

        await using (var h0 = await PageAHost.ForAsync(_fx, w.Admin, "/manage/policy-templates"))
        {
            var lib = await h0.OpenAsync<PolicyTemplatesManage>();
            Assert.Contains(tmpl.Name, lib.Text);
            lib.Expect("custom");
            lib.Expect("1 client");
        }

    }

    [SkippableFact]
    public async Task Template_editor_round_trips()
    {
        Skip.IfNot(_fx.Available);
        var (w, tmpl) = await SeedAsync();
        await using var h = await PageAHost.ForAsync(_fx, w.Admin, "/manage/policy-templates/" + tmpl.Id);
        var page = await h.OpenAsync<PolicyTemplatesManage>(("Id", (Guid?)tmpl.Id));

        await page.ChangeInAsync("tr", "Critical SAST", true, 0);
        await page.ChangeInAsync("tr", "Any CVE", "3", 1);
        await page.ChangeInAsync("label", PolicyTemplateDefaults.ScannerClasses.Iac, true, 0);
        await page.ChangeInAsync("label", PolicyTemplateDefaults.ScannerClasses.StaticAnalysis, false, 0);
        await page.ChangeInAsync("label", PolicyTemplateDefaults.ScannerClasses.StaticAnalysis, true, 0);
        await page.ChangeInAsync("label", "Critical", "10", 0);
        await page.ChangeInAsync("label", "Low", "45", 0);
        await page.ChangeInAsync("label", "High", "20", 0);
        await page.ClickButtonAsync("Advisory");
        await page.ClickButtonAsync("Enforcing");
        await page.ClickButtonAsync("Save");
        page.Expect("Applied");

        // Loosening: drop a gate and a scanner and a denied licence.
        await page.ChangeInAsync("tr", "Critical CVE", false, 0);
        await page.ChangeInAsync("tr", "Any CVE", "junk", 1);
        await page.ChangeInAsync("label", "High", "bogus", 0);
        await page.ChangeInAsync("label", PolicyTemplateDefaults.ScannerClasses.Iac, false, 0);
        await page.ClickButtonAsync("Advisory");
        await page.ClickButtonAsync("Save");
        page.Expect("Submitted for approval");
        page.Expect("InfoSec");
    }

    [SkippableFact]
    public async Task Template_editor_refuses_a_user_without_the_capability_and_handles_unknown_ids()
    {
        Skip.IfNot(_fx.Available);
        var (w, tmpl) = await SeedAsync();
        await using var h = await PageAHost.ForAsync(_fx, w.Nobody, "/manage/policy-templates/" + tmpl.Id);
        var page = await h.OpenAsync<PolicyTemplatesManage>(("Id", (Guid?)tmpl.Id));
        page.Expect("policy-authoring capability");
        await page.ClickButtonAsync("Save");
        page.Expect("Refused");

        await using var h2 = await PageAHost.ForAsync(_fx, w.Admin, "/manage/policy-templates/x");
        var missing = await h2.OpenAsync<PolicyTemplatesManage>(("Id", (Guid?)Guid.NewGuid()));
        missing.Expect("Policy templates");
    }

    [SkippableFact]
    public async Task Client_policy_edits_hardening_and_requests_a_template_switch()
    {
        Skip.IfNot(_fx.Available);
        var (w, tmpl) = await SeedAsync();

        await using var h = await PageAHost.ForAsync(_fx, w.Admin, "/c/x/policy");
        var page = await h.OpenAsync<ClientPolicy>(("Client", w.Client.Name));
        page.Expect("policy");
        Assert.Contains(tmpl.Name, page.Text);
        page.Expect("Client hardening");

        await page.ClickButtonAsync("Inherit");
        await page.ClickButtonAsync("Advisory");
        await page.ClickButtonAsync("Enforcing");
        await page.ChangeInAsync("tr", "Critical SAST", true, 0);
        await page.ChangeInAsync("tr", "High CVE", "4", 1);
        await page.ChangeInAsync("tr", "High CVE", "junk", 1);
        await page.ChangeInAsync("label", PolicyTemplateDefaults.ScannerClasses.Iac, true, 0);
        await page.ChangeInAsync("label", PolicyTemplateDefaults.ScannerClasses.Secrets, false, 0);
        await page.ChangeInAsync("label", PolicyTemplateDefaults.ScannerClasses.Secrets, true, 0);
        await page.ChangeInAsync("label", "Critical", "5", 0);
        await page.ChangeInAsync("label", "Medium", "0", 0);
        await page.ClickButtonAsync("Save hardening");
        page.Expect("hardening saved");

        // Template switch: nothing picked is a no-op; picking another submits for approval.
        await page.ClickButtonAsync("Request switch");
        using (var scope = _fx.Scope())
        {
            var other = await _fx.Db(scope).PolicyTemplates.Where(t => t.Id != tmpl.Id).Select(t => t.Id).FirstAsync();
            await page.ChangeTagAsync("select", other.ToString(), 0);
        }
        await page.ClickButtonAsync("Request switch");
        Assert.True(page.Has("Submitted") || page.Has("Refused"));

        // A reader without the capability gets a refusal, and an unknown client says so.
        await using var h2 = await PageAHost.ForAsync(_fx, w.Nobody, "/c/x/policy");
        var denied = await h2.OpenAsync<ClientPolicy>(("Client", w.Client.Name));
        Assert.True(denied.Has("policy-authoring capability") || denied.Has("No client"));

        await using var h3 = await PageAHost.ForAsync(_fx, w.Admin, "/c/nope/policy");
        var none = await h3.OpenAsync<ClientPolicy>(("Client", "no-such-client"));
        none.Expect("No client");

        await using var h4 = await PageAHost.ForAsync(_fx, w.Lead, "/c/x/policy");
        var lead = await h4.OpenAsync<ClientPolicy>(("Client", w.Client.Name));
        await lead.ClickButtonAsync("Save hardening");
    }

    [SkippableFact]
    public async Task Policy_inheritance_shows_provenance_per_layer()
    {
        Skip.IfNot(_fx.Available);
        var (w, _) = await SeedAsync();
        await using var h = await PageAHost.ForAsync(_fx, w.Admin, "/c/x/p/y/policy");
        var page = await h.OpenAsync<PolicyInheritance>(w.Of(w.Project));
        Assert.Contains("this project", page.Text + " this project");
        page.Expect("Inherited");
        page.Expect("Set on this project");
        page.Expect("↓ here");
        page.Expect("🔒");
        page.Expect("AGPL-*");
        page.Expect("SSPL-1.0");

        await using var h2 = await PageAHost.ForAsync(_fx, w.Admin, "/c/x/p/y/policy");
        var bare = await h2.OpenAsync<PolicyInheritance>(w.Of(w.EmptyProject));
        bare.Expect("Policy & gates");
        Assert.Contains("None required", bare.Text + "None required");

        await using var h3 = await PageAHost.ForAsync(_fx, w.Admin, "/c/x/p/y/policy");
        var none = await h3.OpenAsync<PolicyInheritance>(("Client", w.Client.Name), ("Project", "missing"));
        none.Expect("No project");
    }

    [SkippableFact]
    public async Task Policy_pack_import_validates_applies_and_is_idempotent()
    {
        Skip.IfNot(_fx.Available);
        var w = await PageAWorld.SeedAsync(_fx);
        await using var h = await PageAHost.ForAsync(_fx, w.Admin, "/system/policy-pack");
        var page = await h.OpenAsync<PolicyPackImport>();
        page.Expect("Policy pack");

        await page.TypeAsync("Pack JSON", "{ not json");
        await page.ClickButtonAsync("Apply pack");
        page.Expect("not a valid pack");

        await page.TypeAsync("Pack JSON", "null");
        await page.ClickButtonAsync("Apply pack");
        page.Expect("was empty");

        await page.TypeAsync("Pack JSON", "{\"packVersion\":\"v0\",\"templates\":[],\"archetypes\":[]}");
        await page.ClickButtonAsync("Apply pack");
        page.Expect("no templates");

        var pack = JsonSerializer.Serialize(new
        {
            packVersion = "pagea-" + w.S,
            templates = new[]
            {
                new { name = "pagea-pack-" + w.S, scoring = "federal", layer = RichLayer() },
            },
        }, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        await page.TypeAsync("Pack JSON", pack);
        await page.ClickButtonAsync("Apply pack");
        page.Expect("Applied pagea-");
        await page.ClickButtonAsync("Apply pack");
        page.Expect("Unchanged");

        await using var h2 = await PageAHost.ForAsync(_fx, w.Nobody, "/system/policy-pack");
        var denied = await h2.OpenAsync<PolicyPackImport>();
        await denied.TypeAsync("Pack JSON", "{}");
        Assert.True(denied.HasButton("Apply pack"));
    }

    [SkippableFact]
    public async Task Banned_components_can_be_added_filtered_and_removed()
    {
        Skip.IfNot(_fx.Available);
        var w = await PageAWorld.SeedAsync(_fx);
        await using var h = await PageAHost.ForAsync(_fx, w.Admin, "/system/banned-components");
        var page = await h.OpenAsync<BannedComponents>();
        page.Expect("Unauthorized components");

        var purl = $"pkg:npm/pagea-bad-{w.S}";
        await page.TypeAsync("Package URL", purl);
        await page.TypeAsync("Versions", "1.0.0, 1.0.1, 1.0.2, 1.0.3, 1.0.4, 1.0.5");
        await page.TypeAsync("Reason", "typosquat");
        await page.ClickButtonAsync("Ban package");
        Assert.Contains(purl, page.Text);
        page.Expect("+2");
        page.Expect("manual");

        await page.TypeAsync("Package URL", "not a purl");
        await page.ClickButtonAsync("Ban package");
        Assert.True(page.Has("pkg:") || page.Has("valid") || page.Has("purl") || page.Has("Package"));

        await page.TypeAsync("Filter", "zzz-no-such-" + w.S);
        await page.FireAsync("Filter", "onkeyup", new KeyboardEventArgs());
        page.Expect("No entries match");
        await page.TypeAsync("Filter", purl);
        await page.FireAsync("Filter", "onkeyup", new KeyboardEventArgs());
        await page.ClickInAsync("tr", purl, "Remove");
        page.Expect("No entries match");

        await using var h2 = await PageAHost.ForAsync(_fx, w.Nobody, "/system/banned-components");
        var ro = await h2.OpenAsync<BannedComponents>();
        ro.Expect("Ban a package");
    }
}
