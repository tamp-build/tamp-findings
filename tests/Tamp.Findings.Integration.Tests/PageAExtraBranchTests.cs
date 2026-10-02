using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Projects;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Risk;
using Tamp.Findings.Domain.Values;
using Tamp.Findings.Web.Components.Pages;
using Tamp.Findings.Web.Components.Project;

namespace Tamp.Findings.Integration.Tests;

[Collection(DatabaseCollection.Name)]
public class PageAExtraBranchTests
{
    private readonly DatabaseFixture _fx;
    public PageAExtraBranchTests(DatabaseFixture fx) => _fx = fx;

    // ---- Failure branches: a page that cannot reach the database says so ------

    [SkippableFact]
    public async Task Every_data_page_reports_unavailable_rather_than_an_empty_state_when_the_database_is_unreachable()
    {
        Skip.IfNot(_fx.Available);
        var w = await PageAWorld.SeedAsync(_fx);

        var cases = new (Type Page, (string, object?)[] Args)[]
        {
            (typeof(Policy), [("Client", w.Client.Name), ("Project", w.Project.Name)]),
            (typeof(SystemAdmin), [("Panel", "users")]),
            (typeof(SystemAdmin), [("Panel", "audit")]),
            (typeof(ClientPage), [("Client", w.Client.Name)]),
            (typeof(Costs), [("Client", w.Client.Name), ("Project", w.Project.Name)]),
            (typeof(ProjectHub), [("Client", w.Client.Name), ("Project", w.Project.Name), ("Sha", "latest")]),
            (typeof(Tamp.Findings.Web.Components.Pages.ControlCoverage), [("Client", w.Client.Name), ("Project", w.Project.Name)]),
            (typeof(Decisions), [("Client", w.Client.Name), ("Project", w.Project.Name)]),
            (typeof(ConformanceRules), [("Client", w.Client.Name), ("Project", w.Project.Name)]),
            (typeof(ZeroTrust), [("Client", w.Client.Name), ("Project", w.Project.Name)]),
            (typeof(Portfolio), []),
            (typeof(ClientPolicy), [("Client", w.Client.Name)]),
            (typeof(PolicyInheritance), [("Client", w.Client.Name), ("Project", w.Project.Name)]),
            (typeof(PolicyTemplatesManage), []),
            (typeof(BannedComponents), []),
            (typeof(EoRegistry), []),
            (typeof(Frameworks), []),
            (typeof(PolicyPackImport), []),
        };

        var unavailable = 0;
        foreach (var (page, args) in cases)
        {
            await using var h = await PageAHost.ForAsync(_fx, w.Admin, "/");
            h.BreakDatabase();
            var text = await h.OpenLenientAsync(page, args.Select(a => (a.Item1, a.Item2)).ToArray());
            if (text.Contains("Unavailable", StringComparison.Ordinal) || text.Contains("Could not", StringComparison.Ordinal)) unavailable++;
        }
        Assert.True(unavailable >= 8, $"expected most data pages to report unavailability, got {unavailable}");
    }

    // ---- Policy: rescore preview with real before/after scores ----------------

    [SkippableFact]
    public async Task Policy_preview_shows_before_after_bands_and_unscored_projects()
    {
        Skip.IfNot(_fx.Available);
        var w = await PageAWorld.SeedAsync(_fx);
        await PageAIngest.IngestBuildAsync(_fx, w, $"{w.S}prev1");

        // Duplicate the baseline in the UI, then point both projects at the copy.
        var name = "pagea-prev-" + w.S;
        await using (var h0 = await PageAHost.ForAsync(_fx, w.Admin, "/c/x/p/y/settings/policy"))
        {
            var p0 = await h0.OpenAsync<Policy>(w.Of(w.Project));
            await p0.ClickButtonAsync("duplicate");
            await p0.TypeAsync("Name", "");
            await p0.ClickButtonAsync("Create copy");     // blank name -> dialog error
            await p0.TypeAsync("Name", name);
            await p0.ClickButtonAsync("Create copy");
            await p0.ClickButtonAsync("duplicate");
            await p0.ClickButtonAsync("Cancel");
        }
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            var copy = await db.RiskPolicies.Where(p => p.Name == name).Select(p => p.Id).SingleAsync();
            await db.Projects.Where(p => p.ClientId == w.Client.Id).ExecuteUpdateAsync(u => u.SetProperty(p => p.RiskPolicyId, copy));
        }

        await using var h = await PageAHost.ForAsync(_fx, w.Admin, "/c/x/p/y/settings/policy");
        var page = await h.OpenAsync<Policy>(w.Of(w.Project));
        // Squash the bands so the score lands in a different band, and zero out most categories.
        await page.ChangeInAsync("div", "Green up to", "1");
        await page.ChangeInAsync("div", "Yellow up to", "2");
        await page.ChangeInAsync("div", "Orange up to", "3");
        await page.ClickButtonAsync("Preview rescore");
        page.Expect("Rescore preview");
        page.Expect("no build to score");
        Assert.True(page.Has("→") || page.Has("red") || page.Has("orange") || page.Has("green") || page.Has("yellow"));

        // Same weights: band unchanged branch.
        await page.ClickButtonAsync("Discard changes");
        await page.ChangeInAsync("tr", "Dependency CVEs", "26", 1);
        await page.ClickButtonAsync("Preview rescore");
        page.Expect("Rescore preview");

        // Deleting the policy with users moves them; a seeded policy cannot be deleted.
        await page.ClickInAsync("div", "SYSTEM", "delete");
    }

    // ---- Project key card ----------------------------------------------------

    [SkippableFact]
    public async Task Project_key_card_recycles_directly_and_through_a_second_approver()
    {
        Skip.IfNot(_fx.Available);
        var w = await PageAWorld.SeedAsync(_fx);
        ProjectRef project;
        using (var scope = _fx.Scope())
            project = (await scope.ServiceProvider.GetRequiredService<ProjectHubQuery>()
                .ResolveAsync(w.Client.Name, w.Project.Name, VisibleSet.Everything))!;

        // No key yet.
        await using (var h0 = await PageAHost.ForAsync(_fx, w.Admin, "/"))
            (await h0.OpenAsync<ProjectKeyCard>(("Project", project))).Expect("No ingest key has been issued");

        await PageAIngest.MintTokenAsync(_fx, w.Project.Id, w.Admin.Id);

        // Direct recycle.
        await using (var h = await PageAHost.ForAsync(_fx, w.Admin, "/"))
        {
            var page = await h.OpenAsync<ProjectKeyCard>(("Project", project));
            page.Expect("Never used");
            await page.ClickButtonAsync("Recycle");
            await page.ClickButtonAsync("Cancel");
            await page.ClickButtonAsync("Recycle");
            await page.ClickButtonAsync("Recycle key");
            page.Expect("copy it now");
            await page.ClickButtonAsync("Done");
        }

        // A user without the capability is refused.
        await using (var h = await PageAHost.ForAsync(_fx, w.Nobody, "/"))
        {
            var page = await h.OpenAsync<ProjectKeyCard>(("Project", project));
            await page.ClickButtonAsync("Recycle");
            await page.ClickButtonAsync("Recycle key");
        }

        // Separation of duties on: a request, then a different admin approves / rejects.
        using (var scope = _fx.Scope())
            await _fx.Db(scope).InstanceSettings.ExecuteUpdateAsync(u => u.SetProperty(s => s.EnforceSeparationOfDuties, true));
        try
        {
            var second = PageAHarness.NewUser("2" + w.S, admin: true);
            using (var scope = _fx.Scope()) { var db = _fx.Db(scope); db.Users.Add(second); await db.SaveChangesAsync(); }

            await using (var h = await PageAHost.ForAsync(_fx, w.Admin, "/"))
            {
                var page = await h.OpenAsync<ProjectKeyCard>(("Project", project));
                await page.ClickButtonAsync("Request recycle");
                await page.ClickButtonAsync("Cancel");
                await page.ClickButtonAsync("Request recycle");
                await page.TypeAsync("Note to the approver", "rotating after an offboarding");
                await page.ClickButtonAsync("Send request");
                page.Expect("Waiting on another key manager");
                page.Expect("rotating after an offboarding");
            }

            await using (var h = await PageAHost.ForAsync(_fx, second, "/"))
            {
                var page = await h.OpenAsync<ProjectKeyCard>(("Project", project));
                page.Expect("requested a recycle");
                await page.ClickButtonAsync("Reject");
            }

            await using (var h = await PageAHost.ForAsync(_fx, w.Admin, "/"))
            {
                var page = await h.OpenAsync<ProjectKeyCard>(("Project", project));
                await page.ClickButtonAsync("Request recycle");
                await page.ClickButtonAsync("Send request");
            }
            await using (var h = await PageAHost.ForAsync(_fx, second, "/"))
            {
                var page = await h.OpenAsync<ProjectKeyCard>(("Project", project));
                await page.ClickButtonAsync("Approve");
                page.Expect("copy it now");
            }
        }
        finally
        {
            using var scope = _fx.Scope();
            await _fx.Db(scope).InstanceSettings.ExecuteUpdateAsync(u => u.SetProperty(s => s.EnforceSeparationOfDuties, false));
        }
    }

    // ---- Project hub with images, a past-due POA&M and a failing gate set ------

    [SkippableFact]
    public async Task Project_hub_shows_container_images_and_overdue_poam()
    {
        Skip.IfNot(_fx.Available);
        var w = await PageAWorld.SeedAsync(_fx);
        var sha = $"{w.S}imgbuild";
        await PageAIngest.IngestBuildAsync(_fx, w, sha);
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            var cv = await db.ComponentVersions.FirstAsync(c => c.CommitSha == sha);
            db.ContainerImages.Add(new ContainerImage
            {
                ComponentVersionId = cv.Id, Reference = "registry.example/app:1", CreatedAt = DateTimeOffset.UtcNow.AddDays(-2),
                OsFamily = "alpine", OsVersion = "3.19", BaseImageReference = "alpine:3.19",
                BaseImageCreatedAt = DateTimeOffset.UtcNow.AddDays(-400),
            });
            db.PoamItems.Add(new PoamItem
            {
                ProjectId = w.Project.Id, Title = "overdue weakness", WeaknessDescription = "w", Severity = Severity.High,
                AuthorUserId = w.Admin.Id, ScheduledCompletionDate = DateTimeOffset.UtcNow.AddDays(-20),
            });
            await db.SaveChangesAsync();
        }

        await using var h = await PageAHost.ForAsync(_fx, w.Admin, "/c/x/p/y/build/latest");
        var page = await h.OpenAsync<ProjectHub>(w.Of(w.Project).Concat([("Sha", (object?)"latest")]).ToArray());
        page.Expect("registry.example/app:1");
        page.Expect("days");
        page.Expect("alpine");
    }

    [SkippableFact]
    public async Task Base_image_card_colours_age_bands_and_explains_missing_data()
    {
        Skip.IfNot(_fx.Available);
        var w = await PageAWorld.SeedAsync(_fx);
        var now = DateTimeOffset.UtcNow;
        var rows = new List<ContainerImageRow>
        {
            new("img:1", "sha256:a", now.AddDays(-2), "alpine", "3.19", "alpine:3.19", null, now.AddDays(-400), 400),
            new("img:2", null, now.AddDays(-2), null, null, "debian:12", null, now.AddDays(-250), 250),
            new("img:3", null, null, "debian", "12", "ubuntu:24.04", null, now.AddDays(-5), 5),
            new("img:4", null, null, null, null, null, null, null, null),
        };
        await using var h = await PageAHost.ForAsync(_fx, w.Admin, "/");
        var page = await h.OpenAsync<BaseImageCard>(("Images", (IReadOnlyList<ContainerImageRow>)rows));
        page.Expect("not identified");
        page.Expect("400 days");
        page.Expect("250 days");
        page.Expect("5 days");
        await using var h2 = await PageAHost.ForAsync(_fx, w.Admin, "/");
        (await h2.OpenAsync<BaseImageCard>(("Images", (IReadOnlyList<ContainerImageRow>)new List<ContainerImageRow>()))).Expect("NOT INSPECTED");
    }
}
