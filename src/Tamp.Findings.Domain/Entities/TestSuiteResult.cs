namespace Tamp.Findings.Domain.Entities;

// One row per (TestRunReport, ClassName). AssemblyName tags the module
// (e.g. "Tamp.Findings.Api.Tests") so the SPA tree can group by it.
public sealed class TestSuiteResult
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid TestRunReportId { get; set; }

    public string AssemblyName { get; set; } = "";   // e.g. "Tamp.Findings.Api.Tests"
    public string ClassName { get; set; } = "";      // e.g. "Tamp.Findings.Api.Tests.AggregatesTests"

    public int TotalCount { get; set; }
    public int PassedCount { get; set; }
    public int FailedCount { get; set; }
    public int SkippedCount { get; set; }
    public int InconclusiveCount { get; set; }
    public double DurationMs { get; set; }

    public TestRunReport? Report { get; set; }
    public ICollection<TestCaseResult> Cases { get; set; } = [];
}
