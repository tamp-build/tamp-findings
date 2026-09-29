using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Domain.Entities;

// The raw report file a producer POSTed (a .trx, cobertura, opencover, JUnit), kept as the evidence
// of record for the build. Findings parses these into the canonical model, but the raw file is the
// truth an auditor can re-examine and the source we can re-parse as the model grows (TFND-209).
//
// Stored compressed in its own table so the hot report tables stay lean — it's read only on download
// or re-parse. Replace-by-file with content dedup: the identity for supersession is SlotKey (the
// producer's filename, or "sha256:<hash>" when none was given), so re-posting the same logical file
// replaces it, different files under one build coexist, and identical bytes are a no-op.
public sealed class RawReportArtifact
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid ComponentVersionId { get; set; }

    public RawArtifactKind Kind { get; set; }
    public string Format { get; set; } = "";          // "trx" | "junit" | "cobertura" | "opencover"
    public string? FileName { get; set; }             // producer-supplied, for display; may be null
    public string SlotKey { get; set; } = "";         // replace/dedup identity within (CV, Kind)

    public string Sha256 { get; set; } = "";          // of the raw (uncompressed) bytes
    public long SizeBytes { get; set; }               // uncompressed length
    public byte[] CompressedBytes { get; set; } = [];  // gzip of the raw bytes

    public string? ToolName { get; set; }
    public DateTimeOffset IngestedAt { get; set; } = DateTimeOffset.UtcNow;

    public ComponentVersion? ComponentVersion { get; set; }
}
