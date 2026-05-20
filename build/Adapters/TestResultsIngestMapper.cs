using System.Xml.Linq;
using Tamp.Findings.Build.Ingest;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Build.Adapters;

// Parses TRX (dotnet test --logger trx) into an ingest payload. Multiple
// test projects each emit their own .trx; we union the most-recent batch
// so the dashboard shows a single rolled-up TestRunReport per CV.
public static class TestResultsIngestMapper
{
    public static TestResultsIngestRequestDto? Map(string testResultsRoot, IngestBuildContext ctx)
    {
        if (!Directory.Exists(testResultsRoot)) return null;
        var trxs = Directory.EnumerateFiles(testResultsRoot, "*.trx", SearchOption.AllDirectories)
            .Select(p => new FileInfo(p))
            .OrderByDescending(f => f.LastWriteTimeUtc)
            .ToList();
        if (trxs.Count == 0) return null;

        // Pick the latest batch: every .trx within 10 minutes of the newest
        // file is part of the same test run (dotnet test fans out per
        // project and writes them within seconds of each other).
        var newest = trxs[0].LastWriteTimeUtc;
        var batch = trxs.Where(f => (newest - f.LastWriteTimeUtc).TotalMinutes <= 10).ToList();

        XNamespace ns = "http://microsoft.com/schemas/VisualStudio/TeamTest/2010";
        var classes = new Dictionary<string, ClassAcc>(StringComparer.OrdinalIgnoreCase);
        DateTimeOffset? runStart = null, runEnd = null;
        var totalDuration = 0.0;

        foreach (var fi in batch)
        {
            XDocument doc;
            try { doc = XDocument.Load(fi.FullName); }
            catch { continue; }
            var root = doc.Root;
            if (root is null || root.Name != ns + "TestRun") continue;

            var times = root.Element(ns + "Times");
            if (times is not null)
            {
                // TRX writes local-offset timestamps; Npgsql's "timestamp with time zone"
                // mapping requires UTC, so normalise here.
                if (DateTimeOffset.TryParse((string?)times.Attribute("start"), out var s))
                {
                    var u = s.ToUniversalTime();
                    if (runStart is null || u < runStart) runStart = u;
                }
                if (DateTimeOffset.TryParse((string?)times.Attribute("finish"), out var f))
                {
                    var u = f.ToUniversalTime();
                    if (runEnd is null || u > runEnd) runEnd = u;
                }
            }

            // testId → className via <TestDefinitions><UnitTest><TestMethod/>
            var defs = root.Element(ns + "TestDefinitions")?.Elements(ns + "UnitTest") ?? Enumerable.Empty<XElement>();
            var byTestId = new Dictionary<string, (string ClassName, string AssemblyName)>(StringComparer.OrdinalIgnoreCase);
            foreach (var def in defs)
            {
                var testId = (string?)def.Attribute("id");
                if (testId is null) continue;
                var method = def.Element(ns + "TestMethod");
                var className = (string?)method?.Attribute("className") ?? "(unknown)";
                var codeBase = (string?)method?.Attribute("codeBase") ?? "";
                var assemblyName = AssemblyNameFromCodeBase(codeBase);
                byTestId[testId] = (className, assemblyName);
            }

            foreach (var r in root.Element(ns + "Results")?.Elements(ns + "UnitTestResult") ?? Enumerable.Empty<XElement>())
            {
                var testId = (string?)r.Attribute("testId");
                if (testId is null || !byTestId.TryGetValue(testId, out var meta)) continue;
                var testName = (string?)r.Attribute("testName") ?? "(unknown)";
                // testName includes className prefix — strip it for the row label.
                var shortName = testName.StartsWith(meta.ClassName + ".", StringComparison.Ordinal)
                    ? testName[(meta.ClassName.Length + 1)..]
                    : testName;
                var outcome = MapOutcome((string?)r.Attribute("outcome"));
                var duration = ParseTrxDuration((string?)r.Attribute("duration"));
                totalDuration += duration;

                string? errorMessage = null, errorStack = null;
                var info = r.Element(ns + "Output")?.Element(ns + "ErrorInfo");
                if (info is not null)
                {
                    errorMessage = (string?)info.Element(ns + "Message");
                    errorStack = (string?)info.Element(ns + "StackTrace");
                }

                if (!classes.TryGetValue(meta.ClassName, out var acc))
                {
                    acc = new ClassAcc { ClassName = meta.ClassName, AssemblyName = meta.AssemblyName };
                    classes[meta.ClassName] = acc;
                }
                acc.Cases.Add(new TestCaseDto(shortName, outcome, duration, errorMessage, errorStack));
                acc.Duration += duration;
                switch (outcome)
                {
                    case TestOutcome.Passed: acc.Passed++; break;
                    case TestOutcome.Failed: acc.Failed++; break;
                    case TestOutcome.Skipped: acc.Skipped++; break;
                    default: acc.Inconclusive++; break;
                }
            }
        }

        if (classes.Count == 0) return null;

        var suites = classes.Values
            .OrderBy(c => c.AssemblyName, StringComparer.OrdinalIgnoreCase)
            .ThenBy(c => c.ClassName, StringComparer.OrdinalIgnoreCase)
            .Select(c => new TestSuiteDto(
                AssemblyName: c.AssemblyName,
                ClassName: c.ClassName,
                TotalCount: c.Cases.Count,
                PassedCount: c.Passed,
                FailedCount: c.Failed,
                SkippedCount: c.Skipped,
                InconclusiveCount: c.Inconclusive,
                DurationMs: c.Duration,
                Cases: c.Cases))
            .ToList();

        var total = suites.Sum(s => s.TotalCount);
        var passed = suites.Sum(s => s.PassedCount);
        var failed = suites.Sum(s => s.FailedCount);
        var skipped = suites.Sum(s => s.SkippedCount);
        var inconclusive = suites.Sum(s => s.InconclusiveCount);

        return new TestResultsIngestRequestDto(
            Client: ctx.Client,
            Project: ctx.Project,
            Component: ctx.Component,
            ComponentKind: ctx.ComponentKind,
            Flavor: ctx.Flavor,
            Version: ctx.Version,
            CommitSha: ctx.CommitSha,
            Branch: ctx.Branch,
            BuildId: ctx.BuildId,
            PullRequestRef: ctx.PullRequestRef,
            ToolName: "dotnet test (trx)",
            ToolVersion: null,
            TotalCount: total,
            PassedCount: passed,
            FailedCount: failed,
            SkippedCount: skipped,
            InconclusiveCount: inconclusive,
            DurationMs: totalDuration,
            StartedAt: (runStart ?? DateTimeOffset.UtcNow).ToUniversalTime(),
            CompletedAt: (runEnd ?? DateTimeOffset.UtcNow).ToUniversalTime(),
            Suites: suites);
    }

    private static TestOutcome MapOutcome(string? raw) => raw switch
    {
        "Passed"        => TestOutcome.Passed,
        "Failed"        => TestOutcome.Failed,
        "NotExecuted"   => TestOutcome.Skipped,
        "Inconclusive"  => TestOutcome.Inconclusive,
        _               => TestOutcome.Inconclusive,
    };

    // TRX duration format is "HH:mm:ss.fffffff" — parse to milliseconds.
    private static double ParseTrxDuration(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return 0;
        return TimeSpan.TryParse(raw, out var ts) ? ts.TotalMilliseconds : 0;
    }

    // Extract the test assembly's display name from its codeBase URI/path.
    // Both "C:\path\to\X.dll" and "file:///C:/.../X.dll" forms appear; both
    // should yield "X" — we then keep ".Tests" since the user wants suites
    // grouped by the test assembly, not the SUT.
    private static string AssemblyNameFromCodeBase(string codeBase)
    {
        if (string.IsNullOrWhiteSpace(codeBase)) return "(unknown)";
        var name = Path.GetFileNameWithoutExtension(codeBase);
        return string.IsNullOrWhiteSpace(name) ? "(unknown)" : name;
    }

    private sealed class ClassAcc
    {
        public string ClassName { get; set; } = "";
        public string AssemblyName { get; set; } = "";
        public List<TestCaseDto> Cases { get; } = [];
        public int Passed, Failed, Skipped, Inconclusive;
        public double Duration;
    }
}

public sealed record TestResultsIngestRequestDto(
    string Client,
    string Project,
    string Component,
    string? ComponentKind,
    string? Flavor,
    string Version,
    string? CommitSha,
    string? Branch,
    string? BuildId,
    string? PullRequestRef,
    string ToolName,
    string? ToolVersion,
    int TotalCount,
    int PassedCount,
    int FailedCount,
    int SkippedCount,
    int InconclusiveCount,
    double DurationMs,
    DateTimeOffset StartedAt,
    DateTimeOffset CompletedAt,
    IReadOnlyList<TestSuiteDto> Suites);

public sealed record TestSuiteDto(
    string AssemblyName,
    string ClassName,
    int TotalCount,
    int PassedCount,
    int FailedCount,
    int SkippedCount,
    int InconclusiveCount,
    double DurationMs,
    IReadOnlyList<TestCaseDto> Cases);

public sealed record TestCaseDto(
    string Name,
    TestOutcome Outcome,
    double DurationMs,
    string? ErrorMessage,
    string? ErrorStackTrace);
