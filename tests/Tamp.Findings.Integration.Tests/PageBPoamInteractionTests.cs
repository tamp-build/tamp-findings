using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;
using PoamPage = Tamp.Findings.Web.Components.Pages.Poam;

namespace Tamp.Findings.Integration.Tests;

/// <summary>Drives the POA&amp;M page's dialogs and handlers through an in-process render host.</summary>
[Collection(DatabaseCollection.Name)]
public sealed class PageBPoamInteractionTests(DatabaseFixture fx)
{
    private readonly DatabaseFixture _fx = fx;

    private static Dictionary<string, object?> P(PageBWorld w, string project, Guid? item = null) => new()
    {
        ["Client"] = w.Client, ["Project"] = project, ["ItemId"] = item?.ToString(),
    };

    private static async Task<Guid> ItemAsync(PageBWorld w, Guid projectId, string title, PoamStatus st = PoamStatus.Open,
        int? dueInDays = 10, Severity sev = Severity.High)
    {
        using var scope = w.Host.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<FindingsDbContext>();
        var item = new PoamItem
        {
            ProjectId = projectId, Title = title, WeaknessDescription = title + " weakness", MitigationPlan = "plan", Severity = sev, Status = st,
            ScheduledCompletionDate = dueInDays is null ? null : DateTimeOffset.UtcNow.AddDays(dueInDays.Value), AuthorUserId = PageBWorld.AdminId,
        };
        db.PoamItems.Add(item);
        await db.SaveChangesAsync();
        return item.Id;
    }

    private static async Task<PoamItem> LoadAsync(PageBWorld w, Guid id)
    {
        using var scope = w.Host.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<FindingsDbContext>();
        return await db.PoamItems.AsNoTracking().SingleAsync(i => i.Id == id);
    }

    [SkippableFact]
    public async Task Create_dialog_validates_then_creates_an_item()
    {
        Skip.IfNot(_fx.Available, "TAMP_FINDINGS_TEST_DB not set");
        var w = await PageBWorld.GetAsync(_fx);
        var (name, pid) = await w.NewProjectAsync("poamc");
        await using var page = await PageBRenderHost.RenderAsync<PoamPage>(w, P(w, name));
        Assert.Contains("No POA&M items on this project.", page.Text);

        Assert.True(await page.ClickAsync("New POA&M item"));
        Assert.Contains("Weakness description", page.Text);
        // Blank draft is refused with a reason, and the dialog stays open.
        Assert.True(await page.ClickAsync("Save item"));
        Assert.Contains("Weakness description", page.Text);

        var title = "Created via dialog " + Guid.NewGuid().ToString("N")[..6];
        Assert.True(await page.TypeLabelAsync("Title", title));
        Assert.True(await page.TypeLabelAsync("Weakness description", "Weak TLS configuration"));
        Assert.True(await page.TypeLabelAsync("Mitigation plan", "Upgrade ciphers"));
        Assert.True(await page.TypeLabelAsync("Resources required", "1 engineer"));
        Assert.True(await page.TypeLabelAsync("Reference URL", "https://example.test/t/9"));
        Assert.True(await page.TypeLabelAsync("Scheduled completion", DateTime.UtcNow.AddDays(-3).ToString("yyyy-MM-dd")));
        Assert.True(await page.ClickAsync("CRITICAL"));
        Assert.True(await page.ClickAsync("InProgress"));
        Assert.True(await page.ClickAsync("Save item"));

        Assert.Contains(title, page.Text);
        Assert.Contains("1 overdue item", page.Text);   // scheduled in the past => gate banner
        Assert.True(await page.ClickAsync("See the gates"));
        Assert.Contains("#gates", page.Navigated);
        await using var again = await PageBRenderHost.RenderAsync<PoamPage>(w, P(w, name));
        Assert.Contains(title, again.Text);
        Assert.Empty(page.Errors);
    }

    [SkippableFact]
    public async Task Edit_cancel_and_row_navigation()
    {
        Skip.IfNot(_fx.Available, "TAMP_FINDINGS_TEST_DB not set");
        var w = await PageBWorld.GetAsync(_fx);
        var (name, pid) = await w.NewProjectAsync("poame");
        var id = await ItemAsync(w, pid, "Editable item");
        await ItemAsync(w, pid, "Unscheduled item", dueInDays: null);

        await using var page = await PageBRenderHost.RenderAsync<PoamPage>(w, P(w, name, id));
        Assert.Contains("Editable item weakness", page.Text);
        Assert.Contains("unscheduled", page.Text);
        Assert.True(await page.ClickAsync("Edit"));      // record-view edit
        Assert.True(await page.TypeLabelAsync("Title", "Edited title"));
        Assert.True(await page.ClickAsync("Save item"));
        Assert.Equal("Edited title", (await LoadAsync(w, id)).Title);

        // Row click navigates to the item; the row's edit button opens the dialog; cancel closes it.
        Assert.True(await page.ClickWhereAsync(e => e.Name == "tr"));
        Assert.Contains("/poam/", page.Navigated);
        Assert.True(await page.ClickAsync("edit"));
        Assert.True(await page.ClickAsync("Cancel"));
        Assert.Empty(page.Errors);
    }

    [SkippableFact]
    public async Task Transitions_extension_and_delete_flows()
    {
        Skip.IfNot(_fx.Available, "TAMP_FINDINGS_TEST_DB not set");
        var w = await PageBWorld.GetAsync(_fx);
        var (name, pid) = await w.NewProjectAsync("poamt");
        var id = await ItemAsync(w, pid, "Transition me", dueInDays: -5);

        await using var page = await PageBRenderHost.RenderAsync<PoamPage>(w, P(w, name, id));

        // Extension: blank date is refused, then recorded directly with a reason.
        Assert.True(await page.ClickAsync("Request AO extension"));
        Assert.True(await page.TypeLabelAsync("New scheduled completion", ""));
        Assert.True(await page.ClickAsync("Record extension"));
        Assert.Contains("An extension needs a date.", page.Text);
        Assert.True(await page.ClickAsync("Request AO approval instead"));
        Assert.Contains("An extension needs a date.", page.Text);
        Assert.True(await page.TypeLabelAsync("New scheduled completion", DateTime.UtcNow.AddDays(30).ToString("yyyy-MM-dd")));
        Assert.True(await page.ClickAsync("Request AO approval instead"));
        Assert.Contains("needs a reason", page.Text);
        Assert.True(await page.TypeLabelAsync("Reason", "Vendor patch lands next month"));
        Assert.True(await page.ClickAsync("Record extension"));
        Assert.True((await LoadAsync(w, id)).ScheduledCompletionDate > DateTimeOffset.UtcNow);

        // Mark completed is a direct transition.
        Assert.True(await page.ClickAsync("Mark completed"));
        Assert.Equal(PoamStatus.Completed, (await LoadAsync(w, id)).Status);

        // Delete dialog: the steered-toward option cancels; delete removes.
        var (cancelProject, cancelPid) = await w.NewProjectAsync("poamx");
        var id2 = await ItemAsync(w, cancelPid, "Cancel me");
        await using (var board = await PageBRenderHost.RenderAsync<PoamPage>(w, P(w, cancelProject)))
        {
            Assert.True(await board.ClickWhereAsync(e => e.Name == "button" && e.Text == "delete"));
            Assert.Contains("Delete permanently", board.Text);
            Assert.True(await board.ClickAsync("Cancel & mark cancelled"));
            Assert.Equal(PoamStatus.Cancelled, (await LoadAsync(w, id2)).Status);
            Assert.Empty(board.Errors);
        }

        var (deleteProject, deletePid) = await w.NewProjectAsync("poamd");
        var id3 = await ItemAsync(w, deletePid, "Delete me");
        await using (var board = await PageBRenderHost.RenderAsync<PoamPage>(w, P(w, deleteProject)))
        {
            Assert.True(await board.ClickWhereAsync(e => e.Name == "button" && e.Text == "delete"));
            Assert.True(await board.ClickAsync("Delete permanently"));
            Assert.Contains("/poam", board.Navigated);
            Assert.Empty(await LoadManyAsync(w, deletePid));
            Assert.Empty(board.Errors);
        }
        Assert.NotEqual(Guid.Empty, id3);
        Assert.Empty(page.Errors);
    }

    private static async Task<List<PoamItem>> LoadManyAsync(PageBWorld w, Guid pid)
    {
        using var scope = w.Host.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<FindingsDbContext>();
        return await db.PoamItems.AsNoTracking().Where(i => i.ProjectId == pid).ToListAsync();
    }

    [SkippableFact]
    public async Task Risk_acceptance_request_decide_and_signed_paths()
    {
        Skip.IfNot(_fx.Available, "TAMP_FINDINGS_TEST_DB not set");
        var w = await PageBWorld.GetAsync(_fx);
        var (name, pid) = await w.NewProjectAsync("poamr");
        var accept = await ItemAsync(w, pid, "Accept this");
        var complete = await ItemAsync(w, pid, "Complete this");
        var signed = await ItemAsync(w, pid, "Sign this");

        // Admin requests (cannot decide: lacks AcceptRisk).
        await using (var admin = await PageBRenderHost.RenderAsync<PoamPage>(w, P(w, name, accept)))
        {
            Assert.True(await admin.ClickAsync("Request risk acceptance"));
            Assert.True(await admin.TypeLabelAsync("Why accept this risk?", "Compensating controls exist"));
            Assert.True(await admin.ClickAsync("Send request"));
            Assert.Contains("pending", admin.Text, StringComparison.OrdinalIgnoreCase);
            // A second request for the same decision is refused, not duplicated.
            Assert.Empty(admin.Errors);
        }
        await using (var admin = await PageBRenderHost.RenderAsync<PoamPage>(w, P(w, name, complete)))
        {
            Assert.True(await admin.ClickAsync("Request completion"));
            Assert.True(await admin.TypeLabelAsync("What was done?", "Patched and verified"));
            Assert.True(await admin.ClickAsync("Send request"));
            Assert.Empty(admin.Errors);
        }

        // The ISO sees the decisions awaiting them.
        await using (var iso = await PageBRenderHost.RenderAsync<PoamPage>(w, P(w, name, accept), PageBWorld.Iso))
        {
            Assert.Contains("AWAITING YOU", iso.Text);
            Assert.True(await iso.ClickAsync("show only these"));
            Assert.True(await iso.ClickAsync("show everything"));
            Assert.True(await iso.ClickAsync("Approve risk acceptance"));
            Assert.Contains("Approving moves the item to Risk accepted", iso.Text);
            Assert.True(await iso.ClickAsync("Approve", 0));
            Assert.Equal(PoamStatus.RiskAccepted, (await LoadAsync(w, accept)).Status);
            Assert.Empty(iso.Errors);
        }
        await using (var iso = await PageBRenderHost.RenderAsync<PoamPage>(w, P(w, name, complete), PageBWorld.Iso))
        {
            Assert.True(await iso.ClickAsync("Reject"));
            // Rejection with no reason is refused.
            Assert.True(await iso.ClickWhereAsync(e => e.Name == "button" && e.Text == "Reject", 0));
            Assert.Contains("needs a reason", iso.Text);
            Assert.True(await iso.TypeLabelAsync("Reason for rejecting", "Evidence missing"));
            Assert.True(await iso.ClickWhereAsync(e => e.Name == "button" && e.Text == "Reject", 0));
            Assert.Empty(iso.Errors);
        }

        // Signed self-serve acceptance (instance does not enforce a second approver).
        await using (var iso = await PageBRenderHost.RenderAsync<PoamPage>(w, P(w, name, signed), PageBWorld.Iso))
        {
            if (await iso.ClickAsync("Risk accepted…"))
            {
                var login = Regex.Match(iso.Text, @"Type (\S+) to sign").Groups[1].Value.TrimEnd('.');
                Assert.True(await iso.TypeLabelAsync("Signature", "wrong"));
                Assert.True(await iso.ClickAsync("Sign & accept risk"));
                Assert.True(await iso.TypeLabelAsync("Signature", login));
                Assert.True(await iso.ClickAsync("Sign & accept risk"));
                Assert.Equal(PoamStatus.RiskAccepted, (await LoadAsync(w, signed)).Status);
            }
        }
    }

    [SkippableFact]
    public async Task Viewer_cannot_create_and_missing_project_is_reported()
    {
        Skip.IfNot(_fx.Available, "TAMP_FINDINGS_TEST_DB not set");
        var w = await PageBWorld.GetAsync(_fx);
        await using var viewer = await PageBRenderHost.RenderAsync<PoamPage>(w, P(w, w.Rich), PageBWorld.Viewer);
        Assert.NotEmpty(viewer.Text);
        Assert.False(await viewer.ClickAsync("New POA&M item"));

        await using var missing = await PageBRenderHost.RenderAsync<PoamPage>(w, P(w, "no-such-" + w.Tag));
        Assert.Contains("Project not found", missing.Text);
    }
}
