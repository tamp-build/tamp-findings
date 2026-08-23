using Tamp.Findings.Application.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Projects;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Integration.Tests;

// The project hub against a real database (TFND-77 … TFND-83).
//
// These close the gap the unit tests could not: slug resolution, the joins that
// gather a project's builds, and whether the scorer is actually reached. A
// broken join or a wrong slug comparison passes every contract-level test.
[Collection(DatabaseCollection.Name)]
public class ProjectHubIntegrationTests
{
    private readonly DatabaseFixture _fx;

    public ProjectHubIntegrationTests(DatabaseFixture fx) => _fx = fx;

    [SkippableFact]
    public async Task A_project_resolves_from_its_url_slugs()
    {
        Skip.IfNot(_fx.Available);

        var (client, project, _) = await SeedAsync();
        using var scope = _fx.Scope();
        var hub = scope.ServiceProvider.GetRequiredService<ProjectHubQuery>();

        var resolved = await hub.ResolveAsync(client.Name, project.Name, VisibleSet.Everything /* TFND-133: this test is about the query, not the boundary */);

        Assert.NotNull(resolved);
        Assert.Equal(project.Id, resolved!.ProjectId);
        Assert.Equal(client.Id, resolved.ClientId);
    }

    [SkippableFact]
    public async Task Slug_resolution_is_case_insensitive()
    {
        Skip.IfNot(_fx.Available);

        // A link pasted from a chat window should not 404 on capitals. This is
        // exactly the kind of thing a contract test cannot see, because the
        // comparison happens in SQL.
        var (client, project, _) = await SeedAsync();
        using var scope = _fx.Scope();
        var hub = scope.ServiceProvider.GetRequiredService<ProjectHubQuery>();

        var resolved = await hub.ResolveAsync(
            client.Name.ToUpperInvariant(), project.Name.ToUpperInvariant(),
            VisibleSet.Everything /* TFND-133: this test is about the query, not the boundary */);

        Assert.NotNull(resolved);
    }

    [SkippableFact]
    public async Task A_project_with_no_builds_returns_null_rather_than_a_zero_score()
    {
        Skip.IfNot(_fx.Available);

        var (client, project, _) = await SeedAsync(withBuild: false);
        using var scope = _fx.Scope();
        var hub = scope.ServiceProvider.GetRequiredService<ProjectHubQuery>();

        var resolved = await hub.ResolveAsync(client.Name, project.Name, VisibleSet.Everything /* TFND-133: this test is about the query, not the boundary */);
        var data = await hub.LoadAsync(resolved!, null);

        // Null means "no scan", which the hub renders as such. A zero score
        // would claim something was measured and came back bad.
        Assert.Null(data);
    }

    [SkippableFact]
    public async Task A_seeded_build_produces_a_real_score_and_gate_evaluation()
    {
        Skip.IfNot(_fx.Available);

        var (client, project, _) = await SeedAsync();
        using var scope = _fx.Scope();
        var hub = scope.ServiceProvider.GetRequiredService<ProjectHubQuery>();

        var resolved = await hub.ResolveAsync(client.Name, project.Name, VisibleSet.Everything /* TFND-133: this test is about the query, not the boundary */);
        var data = await hub.LoadAsync(resolved!, null);

        Assert.NotNull(data);
        // Every scored category renders, including the zeros — the point of
        // replacing the six-of-twelve rings.
        Assert.NotEmpty(data!.Risk.Breakdown);
        Assert.NotEmpty(data.Gates.Results);
        Assert.Single(data.History);
    }

    [SkippableFact]
    public async Task An_unscanned_build_reports_unknown_gates_rather_than_passing_them()
    {
        Skip.IfNot(_fx.Available);

        // The end-to-end version of the ADR 0001 defect. Nothing has been
        // ingested against this build, so every severity gate must be
        // unanswerable — not green.
        var (client, project, _) = await SeedAsync(withGates: true);
        using var scope = _fx.Scope();
        var hub = scope.ServiceProvider.GetRequiredService<ProjectHubQuery>();

        var resolved = await hub.ResolveAsync(client.Name, project.Name, VisibleSet.Everything /* TFND-133: this test is about the query, not the boundary */);
        var data = await hub.LoadAsync(resolved!, null);

        Assert.NotNull(data);
        Assert.True(data!.Gates.Unknown > 0, "an unscanned build should have unanswered gates");
        Assert.Equal(0, data.Gates.Passed);
        Assert.False(data.Gates.ClearToShip);
    }

    private async Task<(Client Client, Project Project, ComponentVersion? Build)> SeedAsync(
        bool withBuild = true, bool withGates = false)
    {
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);

        var suffix = Guid.NewGuid().ToString("N")[..8];
        var client = new Client { Name = $"client-{suffix}" };
        var project = new Project { ClientId = client.Id, Name = $"project-{suffix}" };

        if (withGates)
        {
            project.GatesConfig = new Domain.Risk.ProjectGatesConfig();
            foreach (var key in new[] { "criticalSast", "highSast", "criticalDast" })
                project.GatesConfig.Gates[key] = new Domain.Risk.GateConfig { Enabled = true };
        }

        db.Clients.Add(client);
        db.Projects.Add(project);

        ComponentVersion? build = null;
        if (withBuild)
        {
            var component = new Component { ProjectId = project.Id, Name = $"component-{suffix}" };
            build = new ComponentVersion
            {
                ComponentId = component.Id,
                VersionString = "0.1.0",
                CommitSha = suffix + "abcdef",
            };
            db.Components.Add(component);
            db.ComponentVersions.Add(build);
        }

        await db.SaveChangesAsync();
        return (client, project, build);
    }
}
