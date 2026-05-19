namespace Tamp.Findings.Domain.Entities;

public sealed class Component
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid ProjectId { get; set; }
    public required string Name { get; set; }

    // Component kind is free-form for now (e.g., "api", "spa", "library", "container").
    // Will become an enum once the taxonomy stabilises.
    public string? Kind { get; set; }

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    public Project? Project { get; set; }
    public ICollection<ComponentFlavor> Flavors { get; set; } = [];
    public ICollection<ComponentVersion> Versions { get; set; } = [];
}
