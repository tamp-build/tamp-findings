using Tamp.Findings.Domain.Compliance;

namespace Tamp.Findings.Domain.Entities;

public sealed class Component
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid ProjectId { get; set; }
    public required string Name { get; set; }

    // Component kind is free-form for now (e.g., "api", "spa", "library", "container").
    // Will become an enum once the taxonomy stabilises.
    public string? Kind { get; set; }

    // The capability profile (TFND-183): which conditional scanners this
    // component can produce. Declared at ingest; defaults to CodePackage (the
    // safe majority — a library that cannot run DAST/IaC). Drives the
    // intersection rule so a baseline-required scanner it cannot run resolves to
    // N/A-justified, never a false pass.
    public ComponentProfile Profile { get; set; } = ComponentProfile.CodePackage;

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    public Project? Project { get; set; }
    public ICollection<ComponentFlavor> Flavors { get; set; } = [];
    public ICollection<ComponentVersion> Versions { get; set; } = [];
}
