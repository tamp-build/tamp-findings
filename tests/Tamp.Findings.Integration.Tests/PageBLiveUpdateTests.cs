using System.Net;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Projects;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using CategoryPage = Tamp.Findings.Web.Components.Pages.CategoryDetail;
using HubPage = Tamp.Findings.Web.Components.Pages.ProjectHub;

namespace Tamp.Findings.Integration.Tests;

/// <summary>
/// "A build landed" push: an unpinned hub reloads in place, a pinned one only learns a newer build exists,
/// and every page carrying the new-build banner offers a refresh.
/// </summary>
[Collection(DatabaseCollection.Name)]
public sealed class PageBLiveUpdateTests(DatabaseFixture fx)
{
    private readonly DatabaseFixture _fx = fx;

    [SkippableFact]
    public async Task Ingest_push_updates_hub_banner_and_pinned_views()
    {
        Skip.IfNot(_fx.Available, "TAMP_FINDINGS_TEST_DB not set");
        var w = await PageBWorld.GetAsync(_fx);
        var (name, pid, oldSha) = await w.NewBuiltProjectAsync("live");

        await using var latest = await PageBRenderHost.RenderAsync<HubPage>(w,
            new Dictionary<string, object?> { ["Client"] = w.Client, ["Project"] = name, ["Sha"] = "latest" });
        await using var pinned = await PageBRenderHost.RenderAsync<HubPage>(w,
            new Dictionary<string, object?> { ["Client"] = w.Client, ["Project"] = name, ["Sha"] = oldSha });
        await using var banner = await PageBRenderHost.RenderAsync<CategoryPage>(w,
            new Dictionary<string, object?> { ["Client"] = w.Client, ["Project"] = name, ["Sha"] = "latest", ["Key"] = "cve" });
        Assert.DoesNotContain("A newer build", pinned.Text);

        // A newer build lands.
        var newSha = (Guid.NewGuid().ToString("N") + "0000000000")[..40];
        using (var scope = w.Host.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<FindingsDbContext>();
            db.ComponentVersions.Add(new ComponentVersion
            {
                ProjectId = pid, VersionString = "9.9.9", CommitSha = newSha, BranchName = "main", CreatedAt = DateTimeOffset.UtcNow.AddMinutes(5),
            });
            await db.SaveChangesAsync();
        }
        w.Host.Services.GetRequiredService<BuildUpdateNotifier>().Publish(pid);

        // The notifier debounces for 1.5s before it fans out.
        for (var i = 0; i < 30 && !banner.Text.Contains("A newer build has been ingested"); i++) await Task.Delay(200);
        await Task.Delay(500);

        Assert.Contains("A newer build has been ingested", banner.Text);
        Assert.Contains("A newer build", pinned.Text);                 // pinned view only learns of it
        Assert.Contains(newSha[..7], latest.Text);                     // the unpinned hub reloaded onto the new build
        Assert.True(await banner.ClickAsync("Refresh"));
        Assert.Empty(latest.Errors);
        Assert.Empty(pinned.Errors);
    }

    [SkippableFact]
    public async Task Dev_primitives_gallery_renders()
    {
        Skip.IfNot(_fx.Available, "TAMP_FINDINGS_TEST_DB not set");
        var w = await PageBWorld.GetAsync(_fx);
        var (status, body) = await w.GetAsync("/dev/primitives");
        // Only mapped in some environments; when it is, the severity tally renders its zero state.
        if (status == HttpStatusCode.OK) Assert.Contains("none", body);
    }
}
