namespace Tamp.Findings.Domain.Entities;

// One ingested CycloneDX SBOM, scoped to a ComponentVersion. Re-ingesting
// the same ComponentVersion replaces the snapshot rather than appending —
// an SBOM is a point-in-time view, not a stream.
public sealed class SbomSnapshot
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid ComponentVersionId { get; set; }

    public string? SerialNumber { get; set; }   // CycloneDX serialNumber
    public string? SpecVersion { get; set; }    // e.g. "1.5"
    public string? ToolName { get; set; }       // syft / cyclonedx-dotnet
    public string? ToolVersion { get; set; }

    public DateTimeOffset IngestedAt { get; set; } = DateTimeOffset.UtcNow;

    public ComponentVersion? ComponentVersion { get; set; }
    public ICollection<SbomComponent> Components { get; set; } = [];
    public ICollection<SbomDependency> Dependencies { get; set; } = [];
}
