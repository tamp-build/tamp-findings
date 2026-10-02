using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using VexPage = Tamp.Findings.Web.Components.Pages.Vex;

namespace Tamp.Findings.Integration.Tests;

/// <summary>Drives the VEX page's author / retire / publication-request flows through the render host.</summary>
[Collection(DatabaseCollection.Name)]
public sealed class PageBVexInteractionTests(DatabaseFixture fx)
{
    private readonly DatabaseFixture _fx = fx;

    private static Dictionary<string, object?> P(PageBWorld w, string project) => new() { ["Client"] = w.Client, ["Project"] = project };

    private static async Task<List<VexStatement>> StatementsAsync(PageBWorld w, Guid pid)
    {
        using var scope = w.Host.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<FindingsDbContext>();
        return await db.VexStatements.AsNoTracking().Where(v => v.ProjectId == pid).ToListAsync();
    }

    [SkippableFact]
    public async Task Author_edit_and_retire_a_statement()
    {
        Skip.IfNot(_fx.Available, "TAMP_FINDINGS_TEST_DB not set");
        var w = await PageBWorld.GetAsync(_fx);
        var (name, pid) = await w.NewProjectAsync("vexa");
        await using var page = await PageBRenderHost.RenderAsync<VexPage>(w, P(w, name));
        Assert.Contains("No VEX statements on this project.", page.Text);

        Assert.True(await page.ClickAsync("New statement"));
        Assert.True(await page.ClickAsync("Save statement"));          // blank => refused
        Assert.Contains("Advisory", page.Text);

        Assert.True(await page.TypeLabelAsync("Advisory", "CVE-2031-0001"));
        Assert.True(await page.TypeLabelAsync("Package URL", "pkg:nuget/Some.Lib@1.2.3"));
        Assert.True(await page.TypeLabelAsync("Component version", "1.2.3"));
        Assert.True(await page.TypeLabelAsync("Rationale", "Code path is unreachable"));
        Assert.True(await page.TypeLabelAsync("Reference URL", "https://example.test/vex"));
        Assert.True(await page.ClickWhereAsync(e => e.Text == "not_affected"));
        // not_affected without a justification must not be savable.
        Assert.True(await page.ClickAsync("Save statement"));
        Assert.Empty(await VexForAsync(w, pid));
        Assert.True(await page.ClickAsync("vulnerable_code_not_in_execute_path"));
        Assert.True(await page.ClickAsync("Save statement"));

        var saved = await StatementsAsync(w, pid);
        var row = Assert.Single(saved);
        Assert.Equal("CVE-2031-0001", row.AdvisoryId);
        Assert.Equal(VexStatementStatus.NotAffected, row.Status);
        Assert.Equal(VexJustification.VulnerableCodeNotInExecutePath, row.Justification);
        Assert.Contains("/vex", page.Navigated);

        // Reload, edit through a row click, then retire.
        await using var again = await PageBRenderHost.RenderAsync<VexPage>(w, P(w, name));
        Assert.Contains("CVE-2031-0001", again.Text);
        Assert.True(await again.ClickWhereAsync(e => e.Name == "tr" && e.Text.Contains("CVE-2031-0001")));
        Assert.True(await again.TypeLabelAsync("Rationale", "Reworded rationale"));
        Assert.True(await again.ClickAsync("fixed"));
        Assert.True(await again.ClickAsync("Save statement"));
        Assert.Equal(VexStatementStatus.Fixed, (await StatementsAsync(w, pid)).Single().Status);

        await using var third = await PageBRenderHost.RenderAsync<VexPage>(w, P(w, name));
        Assert.True(await third.ClickAsync("retire"));
        Assert.Contains("back into the count", third.Text);
        Assert.True(await third.ClickAsync("Retire statement"));
        Assert.NotNull((await StatementsAsync(w, pid)).Single().RetiredAt);

        Assert.True(await third.CheckNthAsync(0, true));   // show retired
        Assert.Contains("retired", third.Text);
        Assert.True(await third.CheckNthAsync(0, false));
        Assert.Empty(third.Errors);
    }

    private static async Task<List<VexStatement>> VexForAsync(PageBWorld w, Guid pid) => await StatementsAsync(w, pid);

    [SkippableFact]
    public async Task Publication_request_is_decided_by_an_infosec_officer()
    {
        Skip.IfNot(_fx.Available, "TAMP_FINDINGS_TEST_DB not set");
        var w = await PageBWorld.GetAsync(_fx);
        var (name, pid) = await w.NewProjectAsync("vexr");

        // A lead may author but not publish: a relieving statement becomes a request.
        await using (var lead = await PageBRenderHost.RenderAsync<VexPage>(w, P(w, name), PageBWorld.Lead))
        {
            Assert.True(await lead.ClickAsync("New statement"));
            Assert.True(await lead.TypeLabelAsync("Advisory", "CVE-2032-0002"));
            Assert.True(await lead.TypeLabelAsync("Package URL", "pkg:nuget/Req.Lib"));
            Assert.True(await lead.ClickWhereAsync(e => e.Text == "fixed"));
            Assert.True(await lead.ClickAsync("Request publication"));
            Assert.Empty(await StatementsAsync(w, pid));      // nothing published yet
        }

        // A second identical request is refused rather than stacked.
        await using (var lead = await PageBRenderHost.RenderAsync<VexPage>(w, P(w, name), PageBWorld.Lead))
        {
            Assert.Contains("Publication requests", lead.Text);
            Assert.Contains("awaiting an InfoSec officer", lead.Text);
            Assert.True(await lead.ClickAsync("New statement"));
            Assert.True(await lead.TypeLabelAsync("Advisory", "CVE-2032-0002"));
            Assert.True(await lead.TypeLabelAsync("Package URL", "pkg:nuget/Req.Lib"));
            Assert.True(await lead.ClickWhereAsync(e => e.Text == "fixed"));
            Assert.True(await lead.ClickAsync("Request publication"));
            Assert.Contains("already pending", lead.Text);
            // Missing fields and a missing justification are refused with a reason.
            Assert.True(await lead.TypeLabelAsync("Advisory", ""));
            Assert.True(await lead.ClickAsync("Request publication"));
            Assert.Contains("required", lead.Text);
            Assert.True(await lead.TypeLabelAsync("Advisory", "CVE-2032-0003"));
            // not_affected with no justification does not relieve the CVE, so there is nothing to publish.
            Assert.True(await lead.ClickWhereAsync(e => e.Text == "not_affected"));
            Assert.False(await lead.ClickAsync("Request publication"));
        }

        // The ISO approves it: the statement now exists, published.
        await using (var iso = await PageBRenderHost.RenderAsync<VexPage>(w, P(w, name), PageBWorld.Iso))
        {
            Assert.True(await iso.ClickAsync("Reject"));
            Assert.True(await iso.ClickWhereAsync(e => e.Name == "button" && e.Text == "Reject", 0));
            Assert.Contains("needs a reason", iso.Text);
            Assert.True(await iso.TypeLabelAsync("Reason for rejecting", "Not convinced"));
            Assert.True(await iso.ClickWhereAsync(e => e.Name == "button" && e.Text == "Reject", 0));
        }
        // Rejected, so request again and approve this time.
        await using (var lead = await PageBRenderHost.RenderAsync<VexPage>(w, P(w, name), PageBWorld.Lead))
        {
            Assert.True(await lead.ClickAsync("New statement"));
            Assert.True(await lead.TypeLabelAsync("Advisory", "CVE-2032-0004"));
            Assert.True(await lead.TypeLabelAsync("Package URL", "pkg:nuget/Req.Lib2"));
            Assert.True(await lead.ClickWhereAsync(e => e.Text == "fixed"));
            Assert.True(await lead.ClickAsync("Request publication"));
        }
        await using (var iso = await PageBRenderHost.RenderAsync<VexPage>(w, P(w, name), PageBWorld.Iso))
        {
            Assert.True(await iso.ClickAsync("Approve"));
            Assert.Contains("Approving creates the statement", iso.Text);
            Assert.True(await iso.ClickAsync("Approve"));
            Assert.Contains(await StatementsAsync(w, pid), s => s.AdvisoryId == "CVE-2032-0004");
            Assert.Empty(iso.Errors);
        }
    }

    [SkippableFact]
    public async Task Viewer_and_missing_project()
    {
        Skip.IfNot(_fx.Available, "TAMP_FINDINGS_TEST_DB not set");
        var w = await PageBWorld.GetAsync(_fx);
        await using var viewer = await PageBRenderHost.RenderAsync<VexPage>(w, P(w, w.Rich), PageBWorld.Viewer);
        Assert.False(await viewer.ClickAsync("New statement"));
        await using var missing = await PageBRenderHost.RenderAsync<VexPage>(w, P(w, "nope" + w.Tag));
        Assert.Contains("Project not found", missing.Text);

        // The seeded project lists statements; the NOT YET RELIEVING banner counts the open ones.
        await using var admin = await PageBRenderHost.RenderAsync<VexPage>(w, P(w, w.Rich));
        Assert.Contains("NOT YET RELIEVING", admin.Text);
        Assert.Contains("GHSA-5crp-9r3c-p9vr", admin.Text);
    }
}
