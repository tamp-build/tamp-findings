using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Explorer;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Integration.Tests;

// "Why is this package here" (TFND-7 / F6.2).
//
// The edges were ingested from the first SBOM and nothing rendered them. The
// cases that matter are the awkward ones: a package reachable by several
// routes, a graph with a cycle in it (malformed SBOMs have them), and an SBOM
// with no edges at all — which must not look like "nothing depends on this".
[Collection(DatabaseCollection.Name)]
public class DependencyPathIntegrationTests
{
    private readonly DatabaseFixture _fx;

    public DependencyPathIntegrationTests(DatabaseFixture fx) => _fx = fx;

    [SkippableFact]
    public async Task A_direct_dependency_says_so_rather_than_showing_an_empty_list()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var paths = scope.ServiceProvider.GetRequiredService<DependencyPathQuery>();

        var result = await paths.ForAsync(world.ProjectId, null, world.RootPurl);

        Assert.True(result.Direct);
        Assert.Empty(result.Paths);
    }

    [SkippableFact]
    public async Task A_transitive_package_reports_the_route_that_pulled_it_in()
    {
        Skip.IfNot(_fx.Available);

        // root → middle → leaf. The answer a team needs when told they have a
        // critical CVE in something they have never heard of.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var paths = scope.ServiceProvider.GetRequiredService<DependencyPathQuery>();

        var result = await paths.ForAsync(world.ProjectId, null, world.LeafPurl);

        var path = result.Paths.First();
        Assert.Equal(world.RootPurl, path[0].Purl);
        Assert.Equal(world.LeafPurl, path[^1].Purl);
    }

    [SkippableFact]
    public async Task The_path_reads_downwards_from_what_the_team_chose()
    {
        Skip.IfNot(_fx.Available);

        // Built child-first while walking upwards, then reversed. Getting this
        // backwards would put the package the reader already clicked on at the
        // start and the actionable dependency at the end.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var paths = scope.ServiceProvider.GetRequiredService<DependencyPathQuery>();

        var path = (await paths.ForAsync(world.ProjectId, null, world.LeafPurl)).Paths.First();

        Assert.Equal(3, path.Count);
        Assert.Equal(world.MiddlePurl, path[1].Purl);
    }

    [SkippableFact]
    public async Task Several_routes_to_one_package_are_all_reported()
    {
        Skip.IfNot(_fx.Available);

        // The shared package is reachable via the middle AND directly from the
        // root. Reporting one route would tell a team to change a dependency
        // that would not actually remove the package.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var paths = scope.ServiceProvider.GetRequiredService<DependencyPathQuery>();

        var result = await paths.ForAsync(world.ProjectId, null, world.SharedPurl);

        Assert.True(result.Paths.Count >= 2);
    }

    [SkippableFact]
    public async Task The_shortest_route_comes_first()
    {
        Skip.IfNot(_fx.Available);

        // The shortest path is the one with the fewest maintainers between the
        // team and a fix.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var paths = scope.ServiceProvider.GetRequiredService<DependencyPathQuery>();

        var result = await paths.ForAsync(world.ProjectId, null, world.SharedPurl);

        Assert.Equal(2, result.Paths[0].Count);
    }

    [SkippableFact]
    public async Task A_cycle_does_not_hang_the_query()
    {
        Skip.IfNot(_fx.Available);

        // Malformed SBOMs contain cycles. A screen must not hang because
        // somebody's generator emitted a bad edge.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var paths = scope.ServiceProvider.GetRequiredService<DependencyPathQuery>();

        var result = await paths.ForAsync(world.ProjectId, null, world.CyclicPurl);

        // Whatever it returns, it returned.
        Assert.NotNull(result);
    }

    [SkippableFact]
    public async Task An_sbom_with_no_edges_says_so_rather_than_claiming_nothing_depends_on_it()
    {
        Skip.IfNot(_fx.Available);

        // THE distinction. Both are an empty path list and they mean opposite
        // things — one is a limitation of the producer, the other is a claim
        // about the build.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var paths = scope.ServiceProvider.GetRequiredService<DependencyPathQuery>();

        var result = await paths.ForAsync(world.FlatProjectId, null, world.FlatPurl);

        Assert.False(result.HasGraph);
        Assert.False(result.Direct);
    }

    [SkippableFact]
    public async Task A_package_not_in_the_sbom_is_not_reported_as_direct()
    {
        Skip.IfNot(_fx.Available);

        // "Direct dependency" is a claim. An unknown purl must not produce it.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var paths = scope.ServiceProvider.GetRequiredService<DependencyPathQuery>();

        var result = await paths.ForAsync(world.ProjectId, null, "pkg:nuget/Nope@1.0.0");

        Assert.False(result.Direct);
        Assert.Empty(result.Paths);
    }

    // ---- Seed ----------------------------------------------------------------

    private sealed record World(
        Guid ProjectId, Guid FlatProjectId,
        string RootPurl, string MiddlePurl, string LeafPurl, string SharedPurl, string CyclicPurl,
        string FlatPurl);

    private async Task<World> SeedAsync()
    {
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);

        var suffix = Guid.NewGuid().ToString("N")[..8];

        var client = new Client { Name = $"dep-client-{suffix}" };
        var project = new Project { ClientId = client.Id, Name = $"dep-project-{suffix}" };
        var flatProject = new Project { ClientId = client.Id, Name = $"dep-flat-{suffix}" };

        db.Clients.Add(client);
        db.Projects.AddRange(project, flatProject);

        var snapshot = Snapshot(db, project.Id, suffix, "graph");
        var flatSnapshot = Snapshot(db, flatProject.Id, suffix, "flat");

        // root ─┬─ middle ── leaf
        //       │      └───── shared
        //       └───────────── shared        (a second, shorter route)
        //
        // cycleA ⇄ cycleB, with cycleA under root so it is reachable.
        var root = Package(db, snapshot, $"pkg:nuget/Root.{suffix}@1.0.0", "Root");
        var middle = Package(db, snapshot, $"pkg:nuget/Middle.{suffix}@1.0.0", "Middle");
        var leaf = Package(db, snapshot, $"pkg:nuget/Leaf.{suffix}@1.0.0", "Leaf");
        var shared = Package(db, snapshot, $"pkg:nuget/Shared.{suffix}@1.0.0", "Shared");
        var cycleA = Package(db, snapshot, $"pkg:nuget/CycleA.{suffix}@1.0.0", "CycleA");
        var cycleB = Package(db, snapshot, $"pkg:nuget/CycleB.{suffix}@1.0.0", "CycleB");

        Edge(db, snapshot, root.Id, middle.Id);
        Edge(db, snapshot, middle.Id, leaf.Id);
        Edge(db, snapshot, middle.Id, shared.Id);
        Edge(db, snapshot, root.Id, shared.Id);
        Edge(db, snapshot, root.Id, cycleA.Id);
        Edge(db, snapshot, cycleA.Id, cycleB.Id);
        Edge(db, snapshot, cycleB.Id, cycleA.Id);

        // A component list with no edges at all — a real and common producer
        // limitation.
        var flat = Package(db, flatSnapshot, $"pkg:nuget/Flat.{suffix}@1.0.0", "Flat");

        await db.SaveChangesAsync();

        return new World(
            project.Id, flatProject.Id,
            root.Purl, middle.Purl, leaf.Purl, shared.Purl, cycleB.Purl, flat.Purl);
    }

    private static Guid Snapshot(
        Tamp.Findings.Data.FindingsDbContext db, Guid projectId, string suffix, string tag)
    {
        var component = new Component { ProjectId = projectId, Name = tag };
        var version = new ComponentVersion
        {
            ComponentId = component.Id, VersionString = "1.0.0", CommitSha = $"{suffix}{tag}",
        };
        var snapshot = new SbomSnapshot
        {
            ComponentVersionId = version.Id, ToolName = "syft", SpecVersion = "1.5",
        };

        db.Components.Add(component);
        db.ComponentVersions.Add(version);
        db.SbomSnapshots.Add(snapshot);

        return snapshot.Id;
    }

    private static SbomComponent Package(
        Tamp.Findings.Data.FindingsDbContext db, Guid snapshotId, string purl, string name)
    {
        var package = new SbomComponent
        {
            SbomSnapshotId = snapshotId, Purl = purl, Name = name, Version = "1.0.0",
        };
        db.SbomComponents.Add(package);
        return package;
    }

    private static void Edge(
        Tamp.Findings.Data.FindingsDbContext db, Guid snapshotId, Guid parent, Guid child) =>
        db.SbomDependencies.Add(new SbomDependency
        {
            SbomSnapshotId = snapshotId, ParentComponentId = parent, ChildComponentId = child,
        });
}
