namespace Tamp.Findings.Domain.Entities;

// The ZT scored unit (TFND-188 / ADR 0010 §1): a CSAM inventory "system" — which may
// be an app, a data center, a network pipe, a kube cluster, or a database farm. Broader
// than a Project (which is repo/build-shaped), so it is its own node. A repo-backed
// CONSUMER system links a Project (whose build/conformance evidence feeds derivation);
// an infra system links none — it simply has no derived evidence, so every function
// floors at 1 (exactly the conservative default). Belongs to a Client, inheriting the
// client's ZTMM assignment.
public sealed class ZtSystem
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid ClientId { get; set; }
    // Optional: the repo-backed project this system derives evidence from.
    public Guid? ProjectId { get; set; }

    public required string Name { get; set; }
    // The external CSAM inventory id, if any.
    public string? CsamId { get; set; }
    // Free-form role: "app" | "data-center" | "network" | "cluster" | "db-farm".
    public string? SystemKind { get; set; }

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}
