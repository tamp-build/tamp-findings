using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Api.Contracts;

// The optional actor an ingest may carry (TFND-165, wire contract
// tamp-ingest-v1 v1.3). Nested under each hierarchy-bearing request body:
//   "actor": { "id": "pool/3", "kind": "Agent" }
// Kind is Agent | Human, PascalCase on the wire — the default
// JsonStringEnumConverter maps the enum member names, matching the producer.
// Optional and additive: a pre-v1.3 payload omits it and behaves exactly as
// before.
public sealed record IngestActor(string Id, IngestActorKind Kind);

public static class IngestActorExtensions
{
    /// <summary>
    /// Stamp the build with the actor that produced this ingest, when one was
    /// supplied. Absent or blank leaves the build unchanged — so an ingest with
    /// no actor never clears an attribution an earlier one set, and pre-v1.3
    /// producers are a no-op.
    /// </summary>
    public static void ApplyActor(this ComponentVersion version, IngestActor? actor)
    {
        if (actor is null || string.IsNullOrWhiteSpace(actor.Id)) return;
        version.ActorId = actor.Id.Trim();
        version.ActorKind = actor.Kind;
    }
}
