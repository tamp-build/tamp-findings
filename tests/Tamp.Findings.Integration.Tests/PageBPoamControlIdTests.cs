using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;
using PoamPage = Tamp.Findings.Web.Components.Pages.Poam;

namespace Tamp.Findings.Integration.Tests;

/// <summary>
/// Authoring a POA&amp;M item's control mapping through the page (TFND-180), and a
/// regression guard for what finding that field uncovered.
///
/// The guard is the important one. Save built the draft's finding links from _record,
/// which is only loaded when the URL carries an item id — so pressing <em>edit</em> on
/// a row of the board, the ordinary way in, passed an EMPTY list and UpdateAsync wrote
/// it. Every finding link on the item, gone, on an edit that meant to fix a title. It
/// was invisible because the record view's own edit button worked fine, and nothing
/// asserted the links survived an edit.
/// </summary>
[Collection(DatabaseCollection.Name)]
public sealed class PageBPoamControlIdTests(DatabaseFixture fx)
{
    private readonly DatabaseFixture _fx = fx;

    private static Dictionary<string, object?> P(PageBWorld w, string project, Guid? item = null) => new()
    {
        ["Client"] = w.Client, ["Project"] = project, ["ItemId"] = item?.ToString(),
    };

    private static async Task<Guid> ItemAsync(
        PageBWorld w, Guid projectId, string title,
        List<Guid>? links = null, List<string>? controls = null)
    {
        using var scope = w.Host.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<FindingsDbContext>();
        var item = new PoamItem
        {
            ProjectId = projectId,
            Title = title,
            WeaknessDescription = title + " weakness",
            MitigationPlan = "plan",
            Severity = Severity.High,
            Status = PoamStatus.Open,
            ScheduledCompletionDate = DateTimeOffset.UtcNow.AddDays(10),
            AuthorUserId = PageBWorld.AdminId,
            LinkedFindingIds = links ?? [],
            ControlIds = controls ?? [],
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
    public async Task Editing_a_row_from_the_board_keeps_the_finding_links()
    {
        Skip.IfNot(_fx.Available, "TAMP_FINDINGS_TEST_DB not set");
        var w = await PageBWorld.GetAsync(_fx);
        var (name, pid) = await w.NewProjectAsync("poamlinks");

        // Two ids, neither of which resolves to a finding on this project. That is
        // deliberate: rebuilding the list from the links the record RESOLVED would pass
        // a test with real findings and still lose these. An id stops resolving for
        // reasons that are none of the editor's business.
        var links = new List<Guid> { Guid.NewGuid(), Guid.NewGuid() };
        var id = await ItemAsync(w, pid, "Item with links", links: links);

        // No ItemId — the board, which is how an operator arrives.
        await using var page = await PageBRenderHost.RenderAsync<PoamPage>(w, P(w, name));

        Assert.True(await page.ClickAsync("edit"));
        Assert.True(await page.TypeLabelAsync("Title", "Retitled from the board"));
        Assert.True(await page.ClickAsync("Save item"));

        var after = await LoadAsync(w, id);
        Assert.Equal("Retitled from the board", after.Title);
        Assert.Equal(links.OrderBy(x => x), after.LinkedFindingIds.OrderBy(x => x));
        Assert.Empty(page.Errors);
    }

    [SkippableFact]
    public async Task The_dialog_maps_controls_and_normalises_what_was_typed()
    {
        Skip.IfNot(_fx.Available, "TAMP_FINDINGS_TEST_DB not set");
        var w = await PageBWorld.GetAsync(_fx);
        var (name, pid) = await w.NewProjectAsync("poamctl");
        var id = await ItemAsync(w, pid, "Unmapped item");

        await using var page = await PageBRenderHost.RenderAsync<PoamPage>(w, P(w, name, id));
        Assert.Contains("not mapped to a control", page.Text);

        Assert.True(await page.ClickAsync("Edit"));
        // Typed the way someone pastes it out of a document, in OSCAL's own lower-case
        // enhancement form. What lands in the record is the catalog's display form.
        Assert.True(await page.TypeLabelAsync("Affected controls", "cm-6, sc-7 au-2.1"));
        Assert.True(await page.ClickAsync("Save item"));

        var after = await LoadAsync(w, id);
        Assert.Equal(["CM-6", "SC-7", "AU-2(1)"], after.ControlIds);
        Assert.Empty(page.Errors);
    }

    [SkippableFact]
    public async Task A_control_that_does_not_exist_is_refused_in_the_dialog()
    {
        Skip.IfNot(_fx.Available, "TAMP_FINDINGS_TEST_DB not set");
        var w = await PageBWorld.GetAsync(_fx);
        var (name, pid) = await w.NewProjectAsync("poamctlbad");
        var id = await ItemAsync(w, pid, "Item to misspell", controls: ["CM-6"]);

        await using var page = await PageBRenderHost.RenderAsync<PoamPage>(w, P(w, name, id));
        Assert.True(await page.ClickAsync("Edit"));
        Assert.True(await page.TypeLabelAsync("Affected controls", "CM-6, ZZ-99"));
        Assert.True(await page.ClickAsync("Save item"));

        // The dialog says which id it could not find, and the prior mapping is intact —
        // a refusal that silently cleared the field would be worse than the typo.
        Assert.Contains("ZZ-99", page.Text, StringComparison.Ordinal);
        Assert.Equal(["CM-6"], (await LoadAsync(w, id)).ControlIds);
    }
}
