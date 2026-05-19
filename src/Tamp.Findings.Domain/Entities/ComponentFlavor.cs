namespace Tamp.Findings.Domain.Entities;

// A flavor is a build variant of a component that lives alongside its peers
// (e.g., the same library shipped for net8 vs net10). Findings hang off
// ComponentVersion, but flavor lets us partition versions by target without
// duplicating the component identity.
public sealed class ComponentFlavor
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid ComponentId { get; set; }
    public required string Name { get; set; }

    public Component? Component { get; set; }
}
