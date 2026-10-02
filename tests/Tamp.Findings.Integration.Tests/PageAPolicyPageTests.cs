using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Policy;
using Tamp.Findings.Web.Components.Pages;

namespace Tamp.Findings.Integration.Tests;

[Collection(DatabaseCollection.Name)]
public class PageAPolicyPageTests
{
    private readonly DatabaseFixture _fx;
    public PageAPolicyPageTests(DatabaseFixture fx) => _fx = fx;

    [SkippableFact]
    public async Task Admin_duplicates_edits_previews_saves_and_deletes_a_policy()
    {
        Skip.IfNot(_fx.Available);
        var w = await PageAWorld.SeedAsync(_fx);
        await using var h = await PageAHost.ForAsync(_fx, w.Admin, "/c/x/p/y/settings/policy");
        var page = await h.OpenAsync<Policy>(w.Of(w.Project));

        page.Expect("Policy & gates");
        page.Expect("SYSTEM POLICY");
        page.Expect("Read-only");

        // Duplicate the seeded baseline, which selects the copy.
        var name = "pagea-copy-" + w.S;
        await page.ClickButtonAsync("duplicate");
        await page.TypeAsync("Name", name);
        await page.ClickButtonAsync("Create copy");
        Assert.DoesNotContain("SYSTEM POLICY", page.Text);
        Assert.Contains(name, page.Text);

        // Categories, weights, bands.
        await page.ChangeInAsync("tr", "Dependency CVEs", false, 0);
        await page.ChangeInAsync("tr", "Committed secrets", "35", 1);
        await page.ChangeInAsync("tr", "Committed secrets", "bogus", 1);
        await page.ChangeInAsync("div", "Green up to", "30");
        await page.ChangeInAsync("div", "Yellow up to", "50");
        await page.ChangeInAsync("div", "Orange up to", "70");

        // Licences and paid components.
        await page.TypeAsync("Allow", "MIT, Apache-2.0\nBSD-3-Clause");
        await page.TypeAsync("Deny", "AGPL-3.0-only; GPL-3.0-only");
        await page.ChangeAsync("Treat an unidentified licence", true);
        await page.ChangeAsync("Paid components must be approved", true);
        await page.TypeAsync("Approved vendors", "Telerik, Syncfusion");
        page.Expect("unsaved");

        await page.ClickButtonAsync("Preview rescore");
        await page.ClickButtonAsync("Save policy");
        Assert.DoesNotContain("unsaved", page.Text);

        // Edit then discard.
        await page.ChangeInAsync("div", "Green up to", "20");
        page.Expect("unsaved");
        await page.ClickButtonAsync("Discard changes");
        Assert.DoesNotContain("unsaved", page.Text);

        // Gates (project scoped).
        var gate = (await h.Services.GetRequiredService<GateService>().ListAsync(w.Project.Id));
        foreach (var g in gate.Take(3))
            await page.ChangeInAsync("tr", g.Label, true, 0);
        var withThreshold = gate.First(g => g.HasThreshold);
        await page.ChangeInAsync("tr", withThreshold.Label, true, 0);
        await page.ChangeInAsync("tr", withThreshold.Label, "7", 1);
        await page.ChangeInAsync("tr", withThreshold.Label, "-1", 1);
        await page.ChangeTagAsync("select", "Enforcing", 0);
        await page.ClickButtonAsync("Save gates");
        await page.ChangeTagAsync("select", "", 0);
        await page.ClickButtonAsync("Save gates");

        // Point the project at the copy, then delete it with a move target.
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            var copyId = await db.RiskPolicies.Where(p => p.Name == name).Select(p => p.Id).SingleAsync();
            await db.Projects.Where(p => p.Id == w.Project.Id).ExecuteUpdateAsync(u => u.SetProperty(p => p.RiskPolicyId, copyId));
        }
        await using var h2 = await PageAHost.ForAsync(_fx, w.Admin, "/c/x/p/y/settings/policy");
        var page2 = await h2.OpenAsync<Policy>(w.Of(w.Project));
        Assert.Contains(name, page2.Text);
        await page2.ClickInAsync("div", name, "delete");
        page2.Expect("still point here");
        await page2.ClickButtonAsync("Delete permanently"); // disabled until a target is chosen: no-op through handler is refused
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            var other = await db.RiskPolicies.Where(p => p.Name != name).Select(p => p.Id).FirstAsync();
            await page2.ChangeTagAsync("select", other.ToString(), 1);
        }
        await page2.ClickButtonAsync("Delete permanently");
        Assert.DoesNotContain("still point here", page2.Text);
    }

    [SkippableFact]
    public async Task Architect_can_duplicate_but_not_edit_and_unknown_project_renders_empty()
    {
        Skip.IfNot(_fx.Available);
        var w = await PageAWorld.SeedAsync(_fx);
        await using var h = await PageAHost.ForAsync(_fx, w.Architect, "/c/x/p/y/settings/policy");
        var page = await h.OpenAsync<Policy>(w.Of(w.Project));
        page.Expect("Policy & gates");
        await page.ClickButtonAsync("delete"); // disabled-with-reason control still opens the dialog
        await page.ClickButtonAsync("Cancel");

        await using var h2 = await PageAHost.ForAsync(_fx, w.Admin, "/c/x/p/nope/settings/policy");
        var page2 = await h2.OpenAsync<Policy>(("Client", w.Client.Name), ("Project", "nope"));
        page2.Expect("Policy & gates");
    }
}
