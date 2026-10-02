using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Values;
using SettingsPage = Tamp.Findings.Web.Components.Pages.ProjectSettings;

namespace Tamp.Findings.Integration.Tests;

/// <summary>Drives the project settings tabs (tokens, repository, archetype, report, agents, disclosure).</summary>
[Collection(DatabaseCollection.Name)]
public sealed class PageBSettingsInteractionTests(DatabaseFixture fx)
{
    private readonly DatabaseFixture _fx = fx;

    private static Dictionary<string, object?> P(PageBWorld w, string project, string? tab) =>
        new() { ["Client"] = w.Client, ["Project"] = project, ["Tab"] = tab };

    private static async Task<Domain.Entities.Project> LoadAsync(PageBWorld w, Guid pid)
    {
        using var scope = w.Host.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<FindingsDbContext>();
        return await db.Projects.AsNoTracking().SingleAsync(p => p.Id == pid);
    }

    [SkippableFact]
    public async Task Ingest_tokens_mint_revoke_and_repository()
    {
        Skip.IfNot(_fx.Available, "TAMP_FINDINGS_TEST_DB not set");
        var w = await PageBWorld.GetAsync(_fx);
        var (name, pid) = await w.NewProjectAsync("setk");
        await using var page = await PageBRenderHost.RenderAsync<SettingsPage>(w, P(w, name, null));
        Assert.Contains("No ingest tokens on this project.", page.Text);

        Assert.True(await page.ClickAsync("Generate token"));
        Assert.True(await page.ClickAsync("Generate"));                 // blank label refused
        Assert.True(await page.TypeLabelAsync("Label", "ci · pageb"));
        Assert.True(await page.ClickWhereAsync(e => e.Name == "button" && e.Text == "Generate"));
        Assert.Contains("COPY IT NOW", page.Text);
        Assert.Contains("ci · pageb", page.Text);
        Assert.Contains("ACTIVE", page.Text);   // younger than a week, so not yet "never used"

        Assert.True(await page.ClickAsync("revoke"));
        Assert.Contains("Any pipeline still presenting it", page.Text);
        Assert.True(await page.ClickAsync("Cancel"));
        Assert.True(await page.ClickAsync("revoke"));
        Assert.True(await page.ClickWhereAsync(e => e.Name == "button" && e.Text == "Revoke"));
        Assert.Contains("REVOKED", page.Text);

        // Repository: a URL is refused, owner/name is saved.
        Assert.True(await page.TypeLabelAsync("Repository", "https://github.com/acme/app"));
        Assert.True(await page.ClickAsync("Save repository"));
        Assert.Null((await LoadAsync(w, pid)).GitHubRepository);
        Assert.True(await page.TypeLabelAsync("Repository", "acme/app"));
        Assert.True(await page.ClickAsync("Save repository"));
        Assert.Contains("Saved.", page.Text);
        Assert.Equal("acme/app", (await LoadAsync(w, pid)).GitHubRepository);
        Assert.Empty(page.Errors);
    }

    [SkippableFact]
    public async Task Archetype_report_and_disclosure_tabs_save()
    {
        Skip.IfNot(_fx.Available, "TAMP_FINDINGS_TEST_DB not set");
        var w = await PageBWorld.GetAsync(_fx);
        var (name, pid) = await w.NewProjectAsync("setr");

        await using (var arc = await PageBRenderHost.RenderAsync<SettingsPage>(w, P(w, name, "archetype")))
        {
            Assert.True(await arc.TypeLabelAsync("Classification", "1"));
            Assert.True(await arc.ClickAsync("Save classification"));
            Assert.Contains("Saved.", arc.Text);
            Assert.Equal(ProjectArchetype.ContainerAction, (await LoadAsync(w, pid)).Archetype);
            Assert.True(await arc.TypeLabelAsync("Classification", ""));
            Assert.True(await arc.ClickAsync("Save classification"));
            Assert.Null((await LoadAsync(w, pid)).Archetype);
        }

        await using (var rep = await PageBRenderHost.RenderAsync<SettingsPage>(w, P(w, name, "report")))
        {
            Assert.Contains("Private", rep.Text);
            Assert.True(await rep.ClickAsync("Make public"));
            Assert.Contains("Public", rep.Text);
            Assert.True((await LoadAsync(w, pid)).PublicReportEnabled);
            var key1 = (await LoadAsync(w, pid)).ReportKey;
            Assert.True(await rep.ClickAsync("Rotate link"));
            Assert.NotEqual(key1, (await LoadAsync(w, pid)).ReportKey);
            Assert.True(await rep.ClickAsync("Make private"));
            Assert.False((await LoadAsync(w, pid)).PublicReportEnabled);
        }

        await using (var vdp = await PageBRenderHost.RenderAsync<SettingsPage>(w, P(w, name, "disclosure")))
        {
            Assert.Contains("RV.3.1 → No", vdp.Text);
            Assert.True(await vdp.TypeLabelAsync("Security contact", "security@example.test"));
            Assert.True(await vdp.ClickAsync("Save disclosure policy"));
            Assert.Contains("RV.3.1 → Partial", vdp.Text);
            Assert.True(await vdp.TypeLabelAsync("Policy URL", "https://example.test/vdp"));
            Assert.True(await vdp.TypeLabelAsync("Reporting form", "https://example.test/form"));
            Assert.True(await vdp.ClickAsync("Save disclosure policy"));
            Assert.Contains("RV.3.1 → Yes", vdp.Text);
            Assert.Equal("https://example.test/vdp", (await LoadAsync(w, pid)).VdpPolicyUrl);
            // Garbage is rejected with a reason rather than saved.
            Assert.True(await vdp.TypeLabelAsync("Policy URL", "not a url"));
            Assert.True(await vdp.ClickAsync("Save disclosure policy"));
            Assert.Empty(vdp.Errors);
        }

        await using (var acct = await PageBRenderHost.RenderAsync<SettingsPage>(w, P(w, name, "account")))
        {
            Assert.Contains("Signed in as", acct.Text);
            Assert.Contains(name, acct.Text);
        }
    }

    [SkippableFact]
    public async Task Agent_tokens_mint_and_revoke()
    {
        Skip.IfNot(_fx.Available, "TAMP_FINDINGS_TEST_DB not set");
        var w = await PageBWorld.GetAsync(_fx);
        var (name, pid) = await w.NewProjectAsync("seta");
        await using var page = await PageBRenderHost.RenderAsync<SettingsPage>(w, P(w, name, "agents"));
        Assert.Contains("No agent tokens on this project.", page.Text);

        Assert.True(await page.ClickAsync("Mint agent token"));
        Assert.True(await page.ClickWhereAsync(e => e.Name == "button" && e.Text == "Mint"));   // blank label refused
        Assert.True(await page.TypeLabelAsync("Label", "claude · triage"));
        Assert.True(await page.TypeLabelAsync("Acts as", "LeadDev"));
        Assert.True(await page.TypeLabelAsync("Expires in", "30"));
        Assert.True(await page.ClickWhereAsync(e => e.Name == "button" && e.Text == "Mint"));
        Assert.Contains("COPY IT NOW", page.Text);
        Assert.Contains("claude · triage", page.Text);

        Assert.True(await page.ClickAsync("revoke"));
        Assert.Contains("The agent stops reading immediately", page.Text);
        Assert.True(await page.ClickAsync("Cancel"));
        Assert.True(await page.ClickAsync("revoke"));
        Assert.True(await page.ClickWhereAsync(e => e.Name == "button" && e.Text == "Revoke"));
        Assert.Contains("REVOKED", page.Text);
        Assert.Empty(page.Errors);
    }

    [SkippableFact]
    public async Task Viewer_sees_settings_disabled_and_missing_project_is_reported()
    {
        Skip.IfNot(_fx.Available, "TAMP_FINDINGS_TEST_DB not set");
        var w = await PageBWorld.GetAsync(_fx);
        foreach (var who in new[] { PageBWorld.Viewer, PageBWorld.Lead })
        foreach (var tab in new[] { "keys", "archetype", "report", "agents", "disclosure", "account", "bogus" })
        {
            await using var page = await PageBRenderHost.RenderAsync<SettingsPage>(w, P(w, w.Rich, tab), who);
            Assert.NotEmpty(page.Text);
            Assert.Empty(page.Errors);
        }
        await using var viewer = await PageBRenderHost.RenderAsync<SettingsPage>(w, P(w, w.Rich, "keys"), PageBWorld.Viewer);
        Assert.False(await viewer.ClickAsync("Generate token"));
        await using var missing = await PageBRenderHost.RenderAsync<SettingsPage>(w, P(w, "nope" + w.Tag, "keys"));
        Assert.Contains("Project not found", missing.Text);
        await using var seeded = await PageBRenderHost.RenderAsync<SettingsPage>(w, P(w, w.Rich, "keys"));
        Assert.Contains("ci-token", seeded.Text);
        Assert.Contains("REVOKED", seeded.Text);
        await using var agents = await PageBRenderHost.RenderAsync<SettingsPage>(w, P(w, w.Rich, "agents"));
        Assert.Contains("agent-live", agents.Text);
        Assert.Contains("agent-revoked", agents.Text);
    }
}
