namespace Tamp.Findings.Domain.Entities;

// One coverage snapshot per ComponentVersion, latest-wins. Numbers come
// from Coverlet/dotnet-coverage's OpenCover XML (Summary block per
// module + root summary). Sequence coverage is "line coverage" in most
// dashboards; branch coverage is a secondary signal.
public sealed class CoverageReport
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid ComponentVersionId { get; set; }

    public string ToolName { get; set; } = "";          // "Coverlet" / "dotnet-coverage"
    public string? ToolVersion { get; set; }

    public double SequenceCoverage { get; set; }        // 0..100
    public double BranchCoverage { get; set; }
    public int CoveredSequences { get; set; }
    public int TotalSequences { get; set; }
    public int CoveredBranches { get; set; }
    public int TotalBranches { get; set; }

    public DateTimeOffset IngestedAt { get; set; } = DateTimeOffset.UtcNow;

    public ComponentVersion? ComponentVersion { get; set; }
    public ICollection<CoverageModule> Modules { get; set; } = [];
    public ICollection<CoverageSourceFile> SourceFiles { get; set; } = [];
}
