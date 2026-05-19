namespace Tamp.Findings.Domain.Entities;

// One directed edge in the SBOM dep graph (Parent depends on Child).
// We persist edges flat rather than nesting because graph queries are
// easier as joins; reconstruct the tree at read time.
public sealed class SbomDependency
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid SbomSnapshotId { get; set; }
    public Guid ParentComponentId { get; set; }
    public Guid ChildComponentId { get; set; }
}
