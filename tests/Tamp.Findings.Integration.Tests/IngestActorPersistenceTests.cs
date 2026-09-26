using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Integration.Tests;

// The ingest actor persists on the build (TFND-165) — the store half of the
// round-trip. The wire parse and endpoint wiring are covered in Api.Tests; this
// proves the new columns survive a real EF save/read against Postgres, and that a
// build with no actor stays NULL.
[Collection(DatabaseCollection.Name)]
public class IngestActorPersistenceTests
{
    private readonly DatabaseFixture _fx;

    public IngestActorPersistenceTests(DatabaseFixture fx) => _fx = fx;

    [SkippableFact]
    public async Task An_actor_stamped_on_a_build_round_trips_through_the_database()
    {
        Skip.IfNot(_fx.Available);

        Guid versionId;
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            var (_, _, version) = await SeedBuildAsync(db);
            version.ActorId = "pool/3";
            version.ActorKind = IngestActorKind.Agent;
            await db.SaveChangesAsync();
            versionId = version.Id;
        }

        // A fresh scope so the read is from the database, not the tracker.
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            var read = await db.ComponentVersions.AsNoTracking().SingleAsync(v => v.Id == versionId);
            Assert.Equal("pool/3", read.ActorId);
            Assert.Equal(IngestActorKind.Agent, read.ActorKind);
        }
    }

    [SkippableFact]
    public async Task A_build_with_no_actor_stays_null()
    {
        Skip.IfNot(_fx.Available);

        Guid versionId;
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            var (_, _, version) = await SeedBuildAsync(db);
            await db.SaveChangesAsync();
            versionId = version.Id;
        }

        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            var read = await db.ComponentVersions.AsNoTracking().SingleAsync(v => v.Id == versionId);
            Assert.Null(read.ActorId);
            Assert.Null(read.ActorKind);
        }
    }

    private static async Task<(Client, Component, ComponentVersion)> SeedBuildAsync(FindingsDbContext db)
    {
        var suffix = Guid.NewGuid().ToString("N")[..8];
        var client = new Client { Name = $"actor-client-{suffix}" };
        var project = new Project { ClientId = client.Id, Name = $"actor-project-{suffix}" };
        var component = new Component { ProjectId = project.Id, Name = $"actor-component-{suffix}" };
        var version = new ComponentVersion
        {
            ComponentId = component.Id, VersionString = "1.0.0", CommitSha = suffix + "aaaaaa",
        };
        db.Clients.Add(client);
        db.Projects.Add(project);
        db.Components.Add(component);
        db.ComponentVersions.Add(version);
        await db.SaveChangesAsync();
        return (client, component, version);
    }
}
