namespace Tamp.Findings.Domain.Entities;

public sealed class CoverageModule
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid CoverageReportId { get; set; }

    public string Name { get; set; } = "";              // module/assembly name
    public double SequenceCoverage { get; set; }
    public double BranchCoverage { get; set; }
    public int CoveredSequences { get; set; }
    public int TotalSequences { get; set; }

    public CoverageReport? Report { get; set; }
}
