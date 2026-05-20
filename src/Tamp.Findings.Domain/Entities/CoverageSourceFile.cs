namespace Tamp.Findings.Domain.Entities;

// Source file content captured at ingest time so the coverage detail view
// can render red/green line backgrounds without needing access to the
// build host's filesystem. Deduped per (CoverageReport, RelativePath) so
// partial classes that span the same file don't store text twice.
public sealed class CoverageSourceFile
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid CoverageReportId { get; set; }

    public string RelativePath { get; set; } = "";   // e.g. "src/Tamp.Findings.Api/Endpoints/AggregatesEndpoints.cs"
    public string? AbsolutePath { get; set; }        // original absolute path from OpenCover XML (informational)
    public string SourceText { get; set; } = "";     // full file content
    public int LineCount { get; set; }

    public CoverageReport? Report { get; set; }
    public ICollection<CoverageClass> Classes { get; set; } = [];
}
