namespace Tamp.Findings.Domain.Entities;

// One row per (module, class full-name, source-file). Partial classes that
// span multiple files therefore become multiple rows, mirroring OpenCover's
// per-method FileRef structure. LineHits is a jsonb map of
// executable-line-number → visit count (0 = uncovered).
public sealed class CoverageClass
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid CoverageModuleId { get; set; }
    public Guid CoverageSourceFileId { get; set; }

    public string FullName { get; set; } = "";        // e.g. "Tamp.Findings.Api.Endpoints.AggregatesEndpoints"
    public double SequenceCoverage { get; set; }      // 0..100
    public double BranchCoverage { get; set; }
    public int CoveredSequences { get; set; }
    public int TotalSequences { get; set; }
    public int CoveredBranches { get; set; }
    public int TotalBranches { get; set; }

    // Line-level coverage rendered as two arrays so Postgres (Npgsql) can
    // store them as native integer[] without a JSON converter. Lines not in
    // either array are non-executable (comments, blank, decls); the SPA
    // renders those with neutral background.
    public int[] VisitedLines { get; set; } = [];
    public int[] UnvisitedLines { get; set; } = [];

    public CoverageModule? Module { get; set; }
    public CoverageSourceFile? SourceFile { get; set; }
}
