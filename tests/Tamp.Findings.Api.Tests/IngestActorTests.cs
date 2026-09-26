using System.Text.Json;
using System.Text.Json.Serialization;
using Tamp.Findings.Api.Contracts;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Api.Tests;

// The optional ingest actor (TFND-165): parse the v1.3 wire shape, and stamp the
// build with it — or leave the build untouched when it is absent.
public class IngestActorTests
{
    // Mirrors the host's JSON: Web defaults (camelCase, case-insensitive) plus the
    // string enum converter, so "kind": "Agent" binds to the enum member.
    private static readonly JsonSerializerOptions Wire =
        new(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } };

    [Fact]
    public void An_actor_deserializes_from_the_v1_3_wire_shape()
    {
        const string json = """
        { "client":"c","project":"p","component":"cmp","version":"1.0.0",
          "scanner":"Roslyn","findings":[],
          "actor": { "id":"pool/3", "kind":"Agent" } }
        """;

        var req = JsonSerializer.Deserialize<IngestRequest>(json, Wire)!;

        Assert.NotNull(req.Actor);
        Assert.Equal("pool/3", req.Actor!.Id);
        Assert.Equal(IngestActorKind.Agent, req.Actor.Kind);
    }

    [Fact]
    public void Kind_human_is_accepted_pascal_case()
    {
        const string json = """
        { "client":"c","project":"p","component":"cmp","version":"1.0.0",
          "scanner":"Roslyn","findings":[],
          "actor": { "id":"alice", "kind":"Human" } }
        """;

        var req = JsonSerializer.Deserialize<IngestRequest>(json, Wire)!;

        Assert.Equal(IngestActorKind.Human, req.Actor!.Kind);
    }

    [Fact]
    public void A_pre_v1_3_payload_without_an_actor_binds_to_null()
    {
        // Byte-unchanged old payloads must still deserialize, with no actor.
        const string json = """
        { "client":"c","project":"p","component":"cmp","version":"1.0.0",
          "scanner":"Roslyn","findings":[] }
        """;

        var req = JsonSerializer.Deserialize<IngestRequest>(json, Wire)!;

        Assert.Null(req.Actor);
    }

    [Fact]
    public void ApplyActor_stamps_the_build_when_one_is_supplied()
    {
        var v = new ComponentVersion { VersionString = "1.0.0", ComponentId = Guid.NewGuid() };

        v.ApplyActor(new IngestActor("pool/3", IngestActorKind.Agent));

        Assert.Equal("pool/3", v.ActorId);
        Assert.Equal(IngestActorKind.Agent, v.ActorKind);
    }

    [Fact]
    public void ApplyActor_is_a_noop_when_absent_and_never_clears_an_existing_attribution()
    {
        // An ingest with no actor must not wipe an attribution an earlier one set —
        // that is what makes "last ingest to NAME an actor wins" hold.
        var v = new ComponentVersion
        {
            VersionString = "1.0.0", ComponentId = Guid.NewGuid(),
            ActorId = "pool/3", ActorKind = IngestActorKind.Agent,
        };

        v.ApplyActor(null);
        v.ApplyActor(new IngestActor("   ", IngestActorKind.Human));

        Assert.Equal("pool/3", v.ActorId);
        Assert.Equal(IngestActorKind.Agent, v.ActorKind);
    }

    [Fact]
    public void Every_hierarchy_bearing_ingest_endpoint_stamps_the_actor()
    {
        // The five hierarchy-bearing endpoints named in TFND-165. A new one that
        // find-or-creates a build must stamp the actor too, or attribution silently
        // has a hole — so this asserts the call is present on each.
        string[] endpoints =
        [
            "IngestEndpoints", "SbomIngestEndpoints", "CoverageIngestEndpoints",
            "ScanRunIngestEndpoints", "TestResultsEndpoints",
        ];

        foreach (var name in endpoints)
        {
            var src = Source($"src/Tamp.Findings.Api/Endpoints/{name}.cs");
            Assert.Contains("ApplyActor(req.Actor)", src, StringComparison.Ordinal);
        }
    }

    private static string Source(string relativePath)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !Directory.Exists(Path.Combine(dir.FullName, "src")))
            dir = dir.Parent;

        Assert.NotNull(dir);
        var full = Path.Combine(dir!.FullName, relativePath.Replace('/', Path.DirectorySeparatorChar));
        Assert.True(File.Exists(full), $"not found: {full}");
        return File.ReadAllText(full);
    }
}
