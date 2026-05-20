namespace Tamp.Findings.Domain.Values;

public enum TestOutcome
{
    // dotnet test (TRX) emits "Passed", "Failed", "NotExecuted", "Inconclusive".
    // Map to a small canonical set the dashboard renders directly.
    Passed = 0,
    Failed = 1,
    Skipped = 2,
    Inconclusive = 3,
}
