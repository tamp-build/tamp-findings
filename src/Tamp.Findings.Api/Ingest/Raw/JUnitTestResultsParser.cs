using System.Globalization;
using System.Xml.Linq;
using Tamp.Findings.Api.Contracts;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Api.Ingest.Raw;

// JUnit XML (the lingua franca most non-.NET runners emit: pytest, jest, go-junit-report, etc.).
// Root is <testsuites> wrapping many <testsuite>, or a single bare <testsuite>. A <testcase> carries
// classname + name; a child <failure>/<error> marks it failed, <skipped> marks it skipped, otherwise
// it passed. JUnit has no assembly concept, so the suite name stands in as the assembly label.
public static class JUnitTestResultsParser
{
    public static ParsedTestResults Parse(XDocument doc)
    {
        var root = doc.Root ?? throw new RawReportXml.MalformedException("empty junit");
        var testsuites = root.Name.LocalName == "testsuites"
            ? root.Elements().Where(e => e.Name.LocalName == "testsuite")
            : [root];

        var suiteDtos = new List<TestSuiteRequestDto>();
        int total = 0, passed = 0, failed = 0, skipped = 0, inconclusive = 0;
        double totalDuration = 0;

        foreach (var ts in testsuites)
        {
            var suiteName = (string?)ts.Attribute("name") ?? "";
            var cases = new List<TestCaseRequestDto>();
            double suiteDuration = 0;
            string? className = null;

            foreach (var tc in ts.Elements().Where(e => e.Name.LocalName == "testcase"))
            {
                className ??= (string?)tc.Attribute("classname");
                var name = (string?)tc.Attribute("name") ?? "";
                var durationMs = ParseSeconds((string?)tc.Attribute("time"));

                var failure = tc.Elements().FirstOrDefault(e => e.Name.LocalName is "failure" or "error");
                var skip = tc.Elements().FirstOrDefault(e => e.Name.LocalName == "skipped");
                TestOutcome outcome;
                string? message = null, stack = null;
                if (failure is not null)
                {
                    outcome = TestOutcome.Failed;
                    message = (string?)failure.Attribute("message");
                    stack = string.IsNullOrWhiteSpace(failure.Value) ? null : failure.Value.Trim();
                }
                else if (skip is not null)
                {
                    outcome = TestOutcome.Skipped;
                    message = (string?)skip.Attribute("message");
                }
                else
                {
                    outcome = TestOutcome.Passed;
                }

                cases.Add(new TestCaseRequestDto(name, outcome, durationMs, message, stack));
                suiteDuration += durationMs;
            }

            if (cases.Count == 0) continue;

            int p = cases.Count(x => x.Outcome == TestOutcome.Passed);
            int f = cases.Count(x => x.Outcome == TestOutcome.Failed);
            int s = cases.Count(x => x.Outcome == TestOutcome.Skipped);
            int i = cases.Count(x => x.Outcome == TestOutcome.Inconclusive);
            suiteDtos.Add(new TestSuiteRequestDto(
                AssemblyName: suiteName,
                ClassName: string.IsNullOrEmpty(className) ? suiteName : className,
                TotalCount: cases.Count, PassedCount: p, FailedCount: f, SkippedCount: s, InconclusiveCount: i,
                DurationMs: suiteDuration, Cases: cases));
            total += cases.Count; passed += p; failed += f; skipped += s; inconclusive += i;
            totalDuration += suiteDuration;
        }

        return new ParsedTestResults("junit", total, passed, failed, skipped, inconclusive, totalDuration, suiteDtos);
    }

    // JUnit time is fractional seconds ("0.0042"); the canonical model is milliseconds.
    private static double ParseSeconds(string? t) =>
        double.TryParse(t, NumberStyles.Float, CultureInfo.InvariantCulture, out var s) ? s * 1000.0 : 0;
}
