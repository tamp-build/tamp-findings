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

    // TFND-21: CycloneDX metadata.tools — full provenance for which tool(s)
    // generated the SBOM, captured as JSON since CycloneDX 1.5 changed the
    // shape (object with components/services in 1.5, flat array in 1.4).
    public List<Dictionary<string, string?>> MetadataTools { get; set; } = new();

    // TFND-29: SLSA / in-toto build provenance. Stored verbatim as the
    // ingester sent it — either a raw in-toto Statement, a DSSE
    // envelope wrapping the Statement, or a SLSA Provenance document.
    // Type is identified by the JSON's `_type` / `payloadType` /
    // `predicateType` field; the SPA picks the right renderer.
    //
    // Null = no provenance attestation on file → SSDF PS.2.1 evidence
    // falls back to "Partial" when SBOM tool metadata exists, "No"
    // otherwise. Non-null with a SLSA predicate flips PS.2.1 to "Yes".
    public Dictionary<string, object?>? ProvenanceJson { get; set; }
    // Quick-lookup column derived from ProvenanceJson — saves a JSON
    // parse on every attestation render. Examples:
    //   "https://slsa.dev/provenance/v1"   (SLSA v1)
    //   "https://in-toto.io/Statement/v1"  (in-toto Statement)
    //   "application/vnd.dsse.envelope.v1+json" (DSSE envelope)
    // null when no provenance is on file.
    public string? ProvenanceType { get; set; }
    public DateTimeOffset? ProvenanceUploadedAt { get; set; }

    public ComponentVersion? ComponentVersion { get; set; }
    public ICollection<SbomComponent> Components { get; set; } = [];
    public ICollection<SbomDependency> Dependencies { get; set; } = [];
}
