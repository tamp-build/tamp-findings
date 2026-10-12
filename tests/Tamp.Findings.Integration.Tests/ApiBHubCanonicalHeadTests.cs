using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Projects;
using Tamp.Findings.Application.Risk;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Integration.Tests;

/// <summary>
/// The project hub and the gate have to agree about which build they are
/// talking about (TFND-244).
///
/// They did not. `GateDecisionService` filtered to canonical builds — main or
/// master, no pull-request ref — while `ProjectHubQuery` took the 50 most
/// recent `ComponentVersion`s and used `builds[0]`, whatever its branch. So on
/// a project with an open pull request the dashboard scored the PR build while
/// the CLI gate, asked at the same moment, answered about main.
///
/// These seed exactly that shape: a canonical build, and a newer PR build on
/// top of it.
/// </summary>
[Collection(DatabaseCollection.Name)]
public class ApiBHubCanonicalHeadTests
{
    private readonly DatabaseFixture _fx;
    public ApiBHubCanonicalHeadTests(DatabaseFixture fx) => _fx = fx;

    private sealed record World(ProjectRef Project, string MainSha, string PrSha);

    private async Task<World> SeedAsync(bool includeCanonical = true)
    {
        var s = ApiBSupport.Suffix();
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);

        var client = new Client { Name = $"apib-hub-{s}" };
        db.Clients.Add(client);
        var project = new Project { ClientId = client.Id, Name = $"p-{s}" };
        db.Projects.Add(project);

        var mainSha = $"{s}main";
        var prSha = $"{s}pr";

        if (includeCanonical)
        {
            db.ComponentVersions.Add(new ComponentVersion
            {
                ProjectId = project.Id, VersionString = "1.0.0", CommitSha = mainSha,
                BranchName = "main", CreatedAt = DateTimeOffset.UtcNow.AddHours(-3),
            });
        }

        // Newer than main, so it wins any "most recent" ordering.
        db.ComponentVersions.Add(new ComponentVersion
        {
            ProjectId = project.Id, VersionString = "1.1.0-pr", CommitSha = prSha,
            BranchName = "feature/x", PullRequestRef = "42", CreatedAt = DateTimeOffset.UtcNow,
        });

        await db.SaveChangesAsync();

        return new World(
            new ProjectRef(client.Id, client.Name, project.Id, project.Name, null, null),
            mainSha, prSha);
    }

    [SkippableFact]
    public async Task The_default_head_is_main_even_when_a_pr_build_is_newer()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        using var scope = _fx.Scope();
        var hub = scope.ServiceProvider.GetRequiredService<ProjectHubQuery>();

        var data = await hub.LoadAsync(w.Project, commitSha: null);

        Assert.NotNull(data);
        Assert.Equal(w.MainSha, data!.CommitSha);
        Assert.True(data.IsCanonicalBuild);
    }

    [SkippableFact]
    public async Task The_default_head_matches_the_build_the_gate_judges()
    {
        Skip.IfNot(_fx.Available);

        // The actual property under test. Two surfaces, one answer.
        var w = await SeedAsync();
        using var scope = _fx.Scope();
        var hub = scope.ServiceProvider.GetRequiredService<ProjectHubQuery>();
        var gate = scope.ServiceProvider.GetRequiredService<GateDecisionService>();

        var data = await hub.LoadAsync(w.Project, commitSha: null);
        var (status, decision) = await gate.ForLatestAsync(w.Project.ProjectId);

        Assert.Equal(GateDecisionStatus.Ok, status);
        Assert.Equal(decision!.Current.CommitSha, data!.CommitSha);
    }

    [SkippableFact]
    public async Task A_pr_build_is_still_viewable_and_is_labelled_as_not_gated()
    {
        Skip.IfNot(_fx.Available);

        // "Show me the branch I just pushed" survives the fix — it just has to
        // be asked for, and the result says what it is.
        var w = await SeedAsync();
        using var scope = _fx.Scope();
        var hub = scope.ServiceProvider.GetRequiredService<ProjectHubQuery>();

        var data = await hub.LoadAsync(w.Project, w.PrSha);

        Assert.NotNull(data);
        Assert.Equal(w.PrSha, data!.CommitSha);
        Assert.False(data.IsCanonicalBuild);
        Assert.Equal("42", data.PullRequestRef);
        Assert.Equal("feature/x", data.BranchName);
    }

    [SkippableFact]
    public async Task The_not_gated_note_names_the_pull_request()
    {
        Skip.IfNot(_fx.Available);

        // The sentence a reader sees. Computed on ProjectHubData rather than in
        // the Razor template, because a judgement about the evidence that lives
        // in markup is one that goes untested and then wrong.
        var w = await SeedAsync();
        using var scope = _fx.Scope();
        var hub = scope.ServiceProvider.GetRequiredService<ProjectHubQuery>();

        var onPr = await hub.LoadAsync(w.Project, w.PrSha);
        Assert.Contains("Pull request #42", onPr!.NotGatedNote!, StringComparison.Ordinal);
        Assert.Contains("gates judge the latest build on main", onPr.NotGatedNote!, StringComparison.Ordinal);

        // And says nothing at all on the gated build — an unconditional banner
        // would train readers to ignore it.
        var onMain = await hub.LoadAsync(w.Project, commitSha: null);
        Assert.Null(onMain!.NotGatedNote);
    }

    [SkippableFact]
    public async Task The_history_carries_no_pr_builds()
    {
        Skip.IfNot(_fx.Available);

        // A trend line mixing PR builds into main's history would show movement
        // nobody shipped.
        var w = await SeedAsync();
        using var scope = _fx.Scope();
        var hub = scope.ServiceProvider.GetRequiredService<ProjectHubQuery>();

        var data = await hub.LoadAsync(w.Project, commitSha: null);

        Assert.NotNull(data);
        Assert.DoesNotContain(data!.History, h => h.CommitSha == w.PrSha);
        Assert.Contains(data.History, h => h.CommitSha == w.MainSha);
    }

    [SkippableFact]
    public async Task A_project_with_only_pr_builds_reads_as_unscanned_rather_than_falling_back()
    {
        Skip.IfNot(_fx.Available);

        // Falling back to a PR build would reinstate the confusion this fixes.
        // "No scan" is the truth about main, and the hub already renders that
        // state — a project registered but never built is common and must not
        // show a green score.
        var w = await SeedAsync(includeCanonical: false);
        using var scope = _fx.Scope();
        var hub = scope.ServiceProvider.GetRequiredService<ProjectHubQuery>();

        var data = await hub.LoadAsync(w.Project, commitSha: null);

        Assert.Null(data);
    }
}
