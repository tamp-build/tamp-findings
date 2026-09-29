using System.Globalization;
using System.Xml.Linq;
using Tamp.Findings.Api.Contracts;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Api.Ingest.Raw;

// Visual Studio .trx (the default `dotnet test` logger). The fiddly part every hand-rolled adopter
// gets wrong: a <UnitTestResult> only carries a testId + testName; the class name and assembly live
// on a separate <TestDefinitions>/<UnitTest>/<TestMethod>, joined by testId. Owning this join once,
// server-side, is exactly why the raw path exists.
public static class TrxTestResultsParser
{
    private static readonly XNamespace Ns = "http://microsoft.com/schemas/VisualStudio/TeamTest/2010";

    public static ParsedTestResults Parse(XDocument doc)
    {
        var root = doc.Root ?? throw new RawReportXml.MalformedException("empty trx");

        // testId → (assembly, class). storage/codeBase is a full path to the test dll; we want its
        // file name as the assembly label, matching what the normalized producers already send.
        var defs = new Dictionary<string, (string Assembly, string Class)>(StringComparer.OrdinalIgnoreCase);
        foreach (var ut in root.Element(Ns + "TestDefinitions")?.Elements(Ns + "UnitTest") ?? [])
        {
            var id = (string?)ut.Attribute("id");
            if (string.IsNullOrEmpty(id)) continue;
            var tm = ut.Element(Ns + "TestMethod");
            var className = (string?)tm?.Attribute("className") ?? "";
            var storage = (string?)tm?.Attribute("codeBase") ?? (string?)ut.Attribute("storage") ?? "";
            defs[id] = (AssemblyLabel(storage), className);
        }

        // Group cases into suites keyed by (assembly, class). A trx lists results flat under <Results>.
        var suites = new Dictionary<(string Assembly, string Class), List<TestCaseRequestDto>>();
        var durationBySuite = new Dictionary<(string Assembly, string Class), double>();

        foreach (var r in root.Element(Ns + "Results")?.Elements(Ns + "UnitTestResult") ?? [])
        {
            var rawOutcome = (string?)r.Attribute("outcome") ?? "";
            if (string.Equals(rawOutcome, "Completed", StringComparison.OrdinalIgnoreCase))
                continue;   // aggregate/ordered-test container row, not a real test

            var testId = (string?)r.Attribute("testId") ?? "";
            var testName = (string?)r.Attribute("testName") ?? "";
            defs.TryGetValue(testId, out var def);
            var assembly = def.Assembly ?? "";
            var className = def.Class is { Length: > 0 } c ? c : ClassFromTestName(testName);
            var caseName = CaseName(testName, className);

            var outcome = MapOutcome(rawOutcome);
            var durationMs = ParseDuration((string?)r.Attribute("duration"));

            var (message, stack) = ErrorInfo(r);

            var key = (assembly, className);
            if (!suites.TryGetValue(key, out var cases))
            {
                cases = [];
                suites[key] = cases;
                durationBySuite[key] = 0;
            }
            cases.Add(new TestCaseRequestDto(caseName, outcome, durationMs, message, stack));
            durationBySuite[key] += durationMs;
        }

        var suiteDtos = new List<TestSuiteRequestDto>();
        int total = 0, passed = 0, failed = 0, skipped = 0, inconclusive = 0;
        double totalDuration = 0;
        foreach (var (key, cases) in suites)
        {
            int p = cases.Count(x => x.Outcome == TestOutcome.Passed);
            int f = cases.Count(x => x.Outcome == TestOutcome.Failed);
            int s = cases.Count(x => x.Outcome == TestOutcome.Skipped);
            int i = cases.Count(x => x.Outcome == TestOutcome.Inconclusive);
            var dur = durationBySuite[key];
            suiteDtos.Add(new TestSuiteRequestDto(key.Assembly, key.Class, cases.Count, p, f, s, i, dur, cases));
            total += cases.Count; passed += p; failed += f; skipped += s; inconclusive += i;
            totalDuration += dur;
        }

        return new ParsedTestResults("dotnet test (trx)", total, passed, failed, skipped, inconclusive, totalDuration, suiteDtos);
    }

    private static TestOutcome MapOutcome(string outcome) => outcome switch
    {
        "Passed" or "Warning" => TestOutcome.Passed,
        "NotExecuted" => TestOutcome.Skipped,
        "Inconclusive" or "Pending" => TestOutcome.Inconclusive,
        // Failed, Error, Timeout, Aborted, NotRunnable, Disconnected, and anything unexpected read as
        // a failure — an outcome the sink doesn't recognise is not evidence of a pass.
        _ => TestOutcome.Failed,
    };

    private static (string? Message, string? Stack) ErrorInfo(XElement result)
    {
        var err = result.Element(Ns + "Output")?.Element(Ns + "ErrorInfo");
        if (err is null) return (null, null);
        var msg = (string?)err.Element(Ns + "Message");
        var stack = (string?)err.Element(Ns + "StackTrace");
        return (string.IsNullOrWhiteSpace(msg) ? null : msg, string.IsNullOrWhiteSpace(stack) ? null : stack);
    }

    // "00:00:00.0007889" → milliseconds.
    private static double ParseDuration(string? d) =>
        TimeSpan.TryParse(d, CultureInfo.InvariantCulture, out var ts) ? ts.TotalMilliseconds : 0;

    // The test dll path → a stable assembly label (its file name).
    private static string AssemblyLabel(string storage)
    {
        if (string.IsNullOrWhiteSpace(storage)) return "";
        var name = storage.Replace('\\', '/');
        var slash = name.LastIndexOf('/');
        return slash >= 0 ? name[(slash + 1)..] : name;
    }

    // Fallbacks when a result has no matching definition: testName is usually "Namespace.Class.Method".
    private static string ClassFromTestName(string testName)
    {
        var dot = testName.LastIndexOf('.');
        return dot > 0 ? testName[..dot] : testName;
    }

    private static string CaseName(string testName, string className)
    {
        if (!string.IsNullOrEmpty(className) && testName.StartsWith(className + ".", StringComparison.Ordinal))
            return testName[(className.Length + 1)..];
        var dot = testName.LastIndexOf('.');
        return dot >= 0 && dot < testName.Length - 1 ? testName[(dot + 1)..] : testName;
    }
}
