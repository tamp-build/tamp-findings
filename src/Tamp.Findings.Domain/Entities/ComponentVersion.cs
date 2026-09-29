using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Domain.Entities;

public sealed class ComponentVersion
{
    public Guid Id { get; set; } = Guid.NewGuid();

    // TFND (component-collapse PR1): the build is anchored directly to its Project.
    // The old Component tier is being removed — scoring is assigned at the project level
    // and every project had exactly one component. Reads move to ProjectId; ComponentId
    // and Flavor(Id) remain during PR1 so ingest can dual-write and nothing is dropped
    // until the reparent is proven live. PR2 removes ComponentId/FlavorId and the tables.
    public Guid ProjectId { get; set; }

    // The build variant (net10 / web / deployed), formerly a ComponentFlavor row.
    // Kept as a plain tag on the build so variants stay distinguishable without a tier.
    public string? Flavor { get; set; }

    public Guid ComponentId { get; set; }
    public Guid? FlavorId { get; set; }

    public required string VersionString { get; set; }
    public string? CommitSha { get; set; }
    public string? BranchName { get; set; }
    public string? BuildId { get; set; }
    public string? PullRequestRef { get; set; }

    // TFND-165: who produced this build — an agent or a human, and their id
    // (e.g. "pool/3"). Sits alongside the build-context hierarchy above, set from
    // the optional `actor` an ingest may carry. Null for pre-v1.3 producers and
    // for any build no ingest ever attributed, which stay exactly as before.
    // "Attributable by construction" (ADR 0019): the last ingest to name an actor
    // for a build wins, so a build reads as whoever most recently produced
    // evidence for it.
    public string? ActorId { get; set; }
    public IngestActorKind? ActorKind { get; set; }

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    public Project? Project { get; set; }
    public Component? Component { get; set; }
    public ComponentFlavor? FlavorRef { get; set; }
    public ICollection<Finding> Findings { get; set; } = [];
}
