using Tamp.Findings.Domain.Compliance;

namespace Tamp.Findings.Domain.Entities;

/// <summary>
/// An imported control catalog — e.g. NIST SP 800-53 Rev 5 (v3 §6). Its controls
/// are stored inline as jsonb; a catalog is retained even after a newer version
/// is imported, because an attestation cites the catalog version it was signed
/// against and must stay reproducible.
///
/// Seeded with a curated 800-53 subset today; a full OSCAL 1.2 import lands
/// later (TFND-180) and simply adds another catalog row.
/// </summary>
public sealed class ControlCatalog
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public required string Name { get; set; }         // "NIST SP 800-53 Rev 5.2.0"
    public required string Source { get; set; }       // "usnistgov/oscal-content · OSCAL catalog" | "Curated"
    public required string Version { get; set; }      // "5.2.0"
    public string? OscalVersion { get; set; }         // "1.2" once imported from OSCAL
    public string? ImportedSha { get; set; }
    public bool IsSeeded { get; set; }

    /// <summary>True for the catalog the frameworks resolve against right now.
    /// Prior versions are retained but not current.</summary>
    public bool IsCurrent { get; set; }

    public DateTimeOffset ImportedAt { get; set; } = DateTimeOffset.UtcNow;

    /// <summary>The controls, stored as jsonb. Curated subset today (~22);
    /// a full OSCAL import carries the whole ~1,189.</summary>
    public List<Control> Controls { get; set; } = [];
}
