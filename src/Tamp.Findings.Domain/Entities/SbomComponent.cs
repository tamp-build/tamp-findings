namespace Tamp.Findings.Domain.Entities;

// One node in an ingested CycloneDX SBOM. PURL is the natural cross-tool
// identifier ("pkg:nuget/Microsoft.EntityFrameworkCore@10.0.8") — we key
// uniqueness within a SbomSnapshot on (snapshot id, purl).
public sealed class SbomComponent
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid SbomSnapshotId { get; set; }

    public required string Purl { get; set; }
    public required string Name { get; set; }
    public required string Version { get; set; }

    // CycloneDX "type": library, framework, application, container, file, etc.
    public string? Kind { get; set; }
    public string? License { get; set; }

    // Outdatedness annotation (TFND-7 / F6.4). Populated by a separate
    // enrichment step that queries the package registry; null until then.
    public string? LatestVersion { get; set; }
    public DateTimeOffset? LatestReleasedAt { get; set; }
    public DateTimeOffset? CurrentReleasedAt { get; set; }

    public SbomSnapshot? SbomSnapshot { get; set; }
    public ICollection<Vulnerability> Vulnerabilities { get; set; } = [];
}
