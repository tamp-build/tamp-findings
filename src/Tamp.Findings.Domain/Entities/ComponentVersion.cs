using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Domain.Entities;

public sealed class ComponentVersion
{
    public Guid Id { get; set; } = Guid.NewGuid();

    // The build is anchored directly to its Project (component-collapse): the old Component
    // tier was removed because scoring is assigned at the project level and every project had
    // exactly one component. Flavor (net10 / web / deployed), formerly a ComponentFlavor row,
    // is a plain string tag so build variants stay distinguishable without a tier.
    public Guid ProjectId { get; set; }
    public string? Flavor { get; set; }

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
    public ICollection<Finding> Findings { get; set; } = [];
}
