using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Risk;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Integration.Tests;

// TFND-226: a staleness VEX greys a component and takes it out of the score; the closure
// suggestion follows the dependency graph.
[Collection(DatabaseCollection.Name)]
public class StalenessExemptionIntegrationTests
{
    private readonly DatabaseFixture _fx;

    public StalenessExemptionIntegrationTests(DatabaseFixture fx) => _fx = fx;

    private sealed record World(Guid ProjectId, string NetStdPurl, string PlatformsPurl, string SharedPurl);

    private async Task<World> SeedAsync(bool withExemption)
    {
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var suffix = Guid.NewGuid().ToString("N")[..8];

        var client = new Client { Name = $"ex-client-{suffix}" };
        var project = new Project { ClientId = client.Id, Name = $"ex-project-{suffix}" };
        db.Clients.Add(client);
        db.Projects.Add(project);

        var version = new ComponentVersion { ProjectId = project.Id, VersionString = "1.0.0", CommitSha = $"{suffix}ex" };
        var snap = new SbomSnapshot { ComponentVersionId = version.Id, ToolName = "syft", SpecVersion = "1.5" };
        db.ComponentVersions.Add(version);
        db.SbomSnapshots.Add(snap);

        SbomComponent Pkg(string name, string ver, string latest) => new()
        {
            SbomSnapshotId = snap.Id, Purl = $"pkg:nuget/{name}.{suffix}@{ver}", Name = $"{name}.{suffix}", Version = ver,
            LatestVersion = latest, LatestReleasedAt = DateTimeOffset.UtcNow.AddDays(-400),
        };
        // analyzer ── netstd ── platforms ; app ── shared ; analyzer ── shared (shared also ships via app)
        var analyzer = Pkg("Analyzer", "1.0.0", "1.0.0");
        var netstd = Pkg("NetStd", "2.0.3", "2.1.0");
        var platforms = Pkg("Platforms", "1.1.0", "7.0.0");
        var app = Pkg("App", "1.0.0", "1.0.0");
        var shared = Pkg("Shared", "4.5.0", "4.6.0");
        db.SbomComponents.AddRange(analyzer, netstd, platforms, app, shared);
        void Edge(SbomComponent p, SbomComponent c) =>
            db.SbomDependencies.Add(new SbomDependency { SbomSnapshotId = snap.Id, ParentComponentId = p.Id, ChildComponentId = c.Id });
        Edge(analyzer, netstd); Edge(netstd, platforms); Edge(app, shared); Edge(analyzer, shared);

        if (withExemption)
            db.VexStatements.Add(new VexStatement
            {
                ProjectId = project.Id, Purl = $"pkg:nuget/Platforms.{suffix}", ComponentVersion = "1.1.0",
                AdvisoryId = VexStatement.StalenessAdvisoryId, Status = VexStatementStatus.NotAffected,
                Justification = VexJustification.BuildTimeOnly, AuthorUserId = Guid.NewGuid(),
            });

        await db.SaveChangesAsync();
        return new World(project.Id, netstd.Purl, platforms.Purl, shared.Purl);
    }

    [SkippableFact]
    public async Task A_filed_exemption_greys_the_component_and_leaves_the_rest_scored()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync(withExemption: true);
        using var scope = _fx.Scope();
        var q = scope.ServiceProvider.GetRequiredService<CategoryFindingsQuery>();

        var stale = await q.SbomStalenessAsync(w.ProjectId, null);

        Assert.Equal(3, stale.Count);
        Assert.NotNull(stale.Single(c => c.Purl == w.PlatformsPurl).ExemptVexId);
        Assert.Null(stale.Single(c => c.Purl == w.NetStdPurl).ExemptVexId);
        Assert.Equal(PlatformsLast(stale), stale[^1].Purl);
        Assert.Equal(1, (await q.SbomSummaryAsync(w.ProjectId, null))!.Exempt);
    }

    private static string PlatformsLast(IReadOnlyList<StaleComponent> s) => s.Single(c => c.ExemptVexId is not null).Purl;

    [SkippableFact]
    public async Task A_version_bump_reflags_a_version_pinned_exemption()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync(withExemption: true);
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var comp = db.SbomComponents.Single(c => c.Purl == w.PlatformsPurl);
        comp.Version = "1.2.0";
        comp.Purl = w.PlatformsPurl.Replace("@1.1.0", "@1.2.0");
        await db.SaveChangesAsync();
        var q = scope.ServiceProvider.GetRequiredService<CategoryFindingsQuery>();

        var stale = await q.SbomStalenessAsync(w.ProjectId, null);

        Assert.All(stale, c => Assert.Null(c.ExemptVexId));
    }

    [SkippableFact]
    public async Task Closure_suggests_only_components_reachable_solely_through_the_same_roots()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync(withExemption: false);
        using var scope = _fx.Scope();
        var q = scope.ServiceProvider.GetRequiredService<CategoryFindingsQuery>();

        var closure = await q.StalenessClosureAsync(w.ProjectId, null, w.PlatformsPurl);

        // Platforms (clicked) + NetStd (same root: analyzer). Shared is also reachable from App, so it is left out.
        Assert.Contains(closure, c => c.Clicked && c.Purl == w.PlatformsPurl);
        Assert.Contains(closure, c => c.Purl == w.NetStdPurl);
        Assert.DoesNotContain(closure, c => c.Purl == w.SharedPurl);
    }
}
