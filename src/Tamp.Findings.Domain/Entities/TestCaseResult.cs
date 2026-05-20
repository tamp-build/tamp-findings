using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Domain.Entities;

// One row per individual test method. Failed cases keep their error
// message + stack trace so the SPA can render them inline.
public sealed class TestCaseResult
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid TestSuiteResultId { get; set; }

    public string Name { get; set; } = "";           // method name, possibly with [Theory] data suffix
    public TestOutcome Outcome { get; set; }
    public double DurationMs { get; set; }

    public string? ErrorMessage { get; set; }
    public string? ErrorStackTrace { get; set; }

    public TestSuiteResult? Suite { get; set; }
}
