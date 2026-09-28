using Tamp.Findings.Domain.Compliance;

namespace Tamp.Findings.Domain.Entities;

// The versioned ZTMM model (TFND-188 / ADR 0010 §3), parallel to ControlCatalog: one
// IsCurrent row, the pillar/function/stage structure inline as jsonb, refreshed by
// content hash with prior versions retained for reproducibility. Shipped as
// Content/ztmm/ztmm-2.0.json and hash-seeded on startup like the OSCAL catalog.
public sealed class MaturityModelCatalog
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public required string Name { get; set; }        // "CISA ZTMM"
    public required string Version { get; set; }      // "2.0"
    public required string Source { get; set; }       // "CISA, April 2023"
    public string? ImportedSha { get; set; }
    public bool IsSeeded { get; set; }
    public bool IsCurrent { get; set; }
    public DateTimeOffset ImportedAt { get; set; } = DateTimeOffset.UtcNow;
    public List<ZtPillar> Pillars { get; set; } = [];
}
