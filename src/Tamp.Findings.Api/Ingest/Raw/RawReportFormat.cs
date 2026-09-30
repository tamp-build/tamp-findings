using System.Xml.Linq;
using Tamp.Findings.Api.Contracts;

namespace Tamp.Findings.Api.Ingest.Raw;

public enum RawTestFormat { Trx, JUnit }
public enum RawCoverageFormat { Cobertura, OpenCover }

// What a test parser produces: the canonical suite list + roll-up counts, ready to drop into a
// TestResultsIngestRequest. Counts are summed from the cases so a suite's numbers always reconcile
// with the report total, regardless of how the producer's own summary was written.
public sealed record ParsedTestResults(
    string ToolName,
    int TotalCount,
    int PassedCount,
    int FailedCount,
    int SkippedCount,
    int InconclusiveCount,
    double DurationMs,
    IReadOnlyList<TestSuiteRequestDto> Suites);

// What a coverage parser produces: overall totals + per-module breakdown. Line-level class detail is
// intentionally omitted on the raw path — cobertura/opencover carry no source text, and the sink
// drops classes with no source file to overlay, so the normalized endpoint remains the way to ship
// line-level coverage. The overall + module numbers are what the score and coverageFloor gate read.
public sealed record ParsedCoverage(
    string ToolName,
    double SequenceCoverage,
    double BranchCoverage,
    int CoveredSequences,
    int TotalSequences,
    int CoveredBranches,
    int TotalBranches,
    IReadOnlyList<CoverageModuleDto> Modules,
    IReadOnlyList<CoverageSourceFileDto>? SourceFiles = null);

public static class RawReportFormat
{
    // Detect by root element, the one part of each schema that is stable and namespace-tolerant.
    public static RawTestFormat? DetectTest(XDocument doc)
    {
        var root = doc.Root?.Name.LocalName;
        return root switch
        {
            "TestRun" => RawTestFormat.Trx,
            "testsuites" or "testsuite" => RawTestFormat.JUnit,
            _ => null,
        };
    }

    public static RawCoverageFormat? DetectCoverage(XDocument doc)
    {
        var root = doc.Root?.Name.LocalName;
        return root switch
        {
            "coverage" => RawCoverageFormat.Cobertura,
            "CoverageSession" => RawCoverageFormat.OpenCover,
            _ => null,
        };
    }
}
