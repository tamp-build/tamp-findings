using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Explorer;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Integration.Tests;

// The SAST spine's tree and detail against a real database (TFND-86 / TFND-88).
//
// Grouping and ordering are the value of this screen and both happen over real
// rows, so a contract test cannot see them.
[Collection(DatabaseCollection.Name)]
public class ExplorerIntegrationTests
{
    private readonly DatabaseFixture _fx;

    public ExplorerIntegrationTests(DatabaseFixture fx) => _fx = fx;

    [SkippableFact]
    public async Task Findings_group_by_path_prefix_with_the_worst_severity_first()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var query = scope.ServiceProvider.GetRequiredService<FindingsExplorerQuery>();

        var groups = await query.TreeAsync(world.ProjectId, world.Sha, ScannerKinds.Sast);

        var src = groups.Single(g => g.Name == "src");
        // A reader scanning for criticals should not have to read past a
        // hundred info rows, so leaves sort worst-first within their group.
        Assert.Equal(Severity.Critical, src.Files[0].WorstSeverity);
        Assert.True(src.Files[0].WorstSeverity >= src.Files[^1].WorstSeverity);
    }

    [SkippableFact]
    public async Task A_leaf_counts_every_finding_in_that_file()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var query = scope.ServiceProvider.GetRequiredService<FindingsExplorerQuery>();

        var groups = await query.TreeAsync(world.ProjectId, world.Sha, ScannerKinds.Sast);
        var leaf = groups.SelectMany(g => g.Files).Single(f => f.Path == "src/Api/Program.cs");

        Assert.Equal(2, leaf.Count);
        // The badge shows the WORST severity in the file, not the first found.
        Assert.Equal(Severity.Critical, leaf.WorstSeverity);
    }

    [SkippableFact]
    public async Task Detail_returns_the_findings_for_one_file_worst_first()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var query = scope.ServiceProvider.GetRequiredService<FindingsExplorerQuery>();

        var detail = await query.DetailAsync(world.ProjectId, world.Sha, ScannerKinds.Sast, "src/Api/Program.cs");

        Assert.Equal(2, detail.Count);
        Assert.Equal(Severity.Critical, detail[0].Severity);
    }

    [SkippableFact]
    public async Task A_finding_with_no_file_path_is_visible_rather_than_grouped_under_nothing()
    {
        Skip.IfNot(_fx.Available);

        // Silently bucketing these under "" would hide them entirely — the
        // reader would never know the finding existed.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var query = scope.ServiceProvider.GetRequiredService<FindingsExplorerQuery>();

        var groups = await query.TreeAsync(world.ProjectId, world.Sha, ScannerKinds.Sast);

        Assert.Contains(groups, g => g.Name == "(no file)");
    }

    [SkippableFact]
    public async Task Suppressed_and_closed_findings_do_not_appear()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var query = scope.ServiceProvider.GetRequiredService<FindingsExplorerQuery>();

        var all = (await query.TreeAsync(world.ProjectId, world.Sha, ScannerKinds.Sast))
            .SelectMany(g => g.Files).ToArray();

        Assert.DoesNotContain(all, f => f.Path == "src/Closed.cs");
    }

    private sealed record World(Guid ProjectId, string Sha);

    private async Task<World> SeedAsync()
    {
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);

        var suffix = Guid.NewGuid().ToString("N")[..8];
        var sha = suffix + "aaaaaa";
        var client = new Client { Name = $"ex-client-{suffix}" };
        var project = new Project { ClientId = client.Id, Name = $"ex-project-{suffix}" };
        var component = new Component { ProjectId = project.Id, Name = $"ex-component-{suffix}" };
        var version = new ComponentVersion
        {
            ComponentId = component.Id, VersionString = "0.1.0", CommitSha = sha,
        };

        db.Clients.Add(client);
        db.Projects.Add(project);
        db.Components.Add(component);
        db.ComponentVersions.Add(version);

        var scanner = ScannerKinds.Sast.First();

        void Finding(string? path, Severity severity, FindingStatus status = FindingStatus.Open) =>
            db.Findings.Add(new Finding
            {
                ComponentVersionId = version.Id,
                Hash = Guid.NewGuid().ToString("N"),
                Scanner = scanner,
                RuleId = "RULE001",
                Severity = severity,
                Title = $"{severity} in {path ?? "nowhere"}",
                FilePath = path,
                Status = status,
            });

        Finding("src/Api/Program.cs", Severity.Critical);
        Finding("src/Api/Program.cs", Severity.Low);
        Finding("src/Api/Other.cs", Severity.Medium);
        Finding("tests/Thing.cs", Severity.Info);
        Finding(null, Severity.High);
        Finding("src/Closed.cs", Severity.Critical, FindingStatus.Suppressed);

        await db.SaveChangesAsync();
        return new World(project.Id, sha);
    }
}
