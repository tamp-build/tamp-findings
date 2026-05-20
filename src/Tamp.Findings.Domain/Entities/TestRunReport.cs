namespace Tamp.Findings.Domain.Entities;

// One test-run snapshot per ComponentVersion (latest-wins). Mirrors the
// CoverageReport pattern — a re-run for the same CV replaces the prior
// report and its suites/cases via cascade delete.
public sealed class TestRunReport
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid ComponentVersionId { get; set; }

    public string ToolName { get; set; } = "";       // "dotnet test (trx)"
    public string? ToolVersion { get; set; }

    public int TotalCount { get; set; }
    public int PassedCount { get; set; }
    public int FailedCount { get; set; }
    public int SkippedCount { get; set; }
    public int InconclusiveCount { get; set; }

    public double DurationMs { get; set; }
    public DateTimeOffset StartedAt { get; set; }
    public DateTimeOffset CompletedAt { get; set; }
    public DateTimeOffset IngestedAt { get; set; } = DateTimeOffset.UtcNow;

    public ComponentVersion? ComponentVersion { get; set; }
    public ICollection<TestSuiteResult> Suites { get; set; } = [];
}
