using System.Text;
using System.Xml.Linq;
using Tamp.Findings.Api.Ingest.Raw;
using Tamp.Findings.Domain.Values;
using Xunit;

namespace Tamp.Findings.Api.Tests;

// The raw-ingest parsers (TFND: kill the mapper gap). The sink owns the reshape from a CI producer's
// native report into the canonical model, so these are the tests that keep the fiddly bits — the trx
// testId join, JUnit outcome mapping, cobertura rate scaling, XXE hardening — honest.
public class RawReportParserTests
{
    // ---- .trx (real fixture) -------------------------------------------------------------------

    [Fact]
    public void Trx_parses_a_real_dotnet_test_report()
    {
        var doc = Load(FindTrx());
        Assert.Equal(RawTestFormat.Trx, RawReportFormat.DetectTest(doc));

        var r = TrxTestResultsParser.Parse(doc);
        Assert.Equal("dotnet test (trx)", r.ToolName);
        Assert.True(r.TotalCount > 0);
        Assert.Equal(r.TotalCount, r.PassedCount + r.FailedCount + r.SkippedCount + r.InconclusiveCount);
        Assert.Equal(r.TotalCount, r.Suites.Sum(s => s.TotalCount));
        Assert.All(r.Suites, s => Assert.EndsWith(".dll", s.AssemblyName, StringComparison.OrdinalIgnoreCase));
        Assert.All(r.Suites, s => Assert.NotEmpty(s.ClassName));
        // The case name is the method, not the fully-qualified name (the class prefix is stripped).
        Assert.All(r.Suites.SelectMany(s => s.Cases), c => Assert.DoesNotContain('.', c.Name));
    }

    // ---- JUnit (inline) ------------------------------------------------------------------------

    [Fact]
    public void JUnit_maps_pass_fail_skip_and_captures_the_failure_message()
    {
        const string xml = """
        <testsuites>
          <testsuite name="pkg.Suite" tests="3" failures="1" skipped="1">
            <testcase classname="pkg.Alpha" name="passes" time="0.010" />
            <testcase classname="pkg.Alpha" name="breaks" time="0.020">
              <failure message="expected 1 got 2">at pkg.Alpha.breaks()</failure>
            </testcase>
            <testcase classname="pkg.Alpha" name="ignored" time="0">
              <skipped message="not ready" />
            </testcase>
          </testsuite>
        </testsuites>
        """;
        var doc = XDocument.Parse(xml);
        Assert.Equal(RawTestFormat.JUnit, RawReportFormat.DetectTest(doc));

        var r = JUnitTestResultsParser.Parse(doc);
        Assert.Equal(3, r.TotalCount);
        Assert.Equal(1, r.PassedCount);
        Assert.Equal(1, r.FailedCount);
        Assert.Equal(1, r.SkippedCount);
        var suite = Assert.Single(r.Suites);
        Assert.Equal("pkg.Alpha", suite.ClassName);
        Assert.Equal(30, suite.DurationMs);   // seconds → ms
        var failed = Assert.Single(suite.Cases, c => c.Outcome == TestOutcome.Failed);
        Assert.Equal("expected 1 got 2", failed.ErrorMessage);
        Assert.Contains("breaks()", failed.ErrorStackTrace);
    }

    // ---- Cobertura (inline) --------------------------------------------------------------------

    [Fact]
    public void Cobertura_scales_rates_and_counts_lines()
    {
        const string xml = """
        <coverage line-rate="0.75" branch-rate="0.5" lines-covered="3" lines-valid="4" branches-covered="1" branches-valid="2">
          <packages>
            <package name="Pkg.A" line-rate="0.75" branch-rate="0.5">
              <classes>
                <class name="Pkg.A.C" filename="src/C.cs" line-rate="0.75">
                  <lines>
                    <line number="1" hits="5" />
                    <line number="2" hits="1" />
                    <line number="3" hits="0" />
                    <line number="4" hits="2" />
                  </lines>
                </class>
              </classes>
            </package>
          </packages>
        </coverage>
        """;
        var doc = XDocument.Parse(xml);
        Assert.Equal(RawCoverageFormat.Cobertura, RawReportFormat.DetectCoverage(doc));

        var r = CoberturaCoverageParser.Parse(doc);
        Assert.Equal("cobertura", r.ToolName);
        Assert.Equal(75, r.SequenceCoverage);     // line-rate 0.75 → 75%
        Assert.Equal(3, r.CoveredSequences);
        Assert.Equal(4, r.TotalSequences);
        Assert.Equal(1, r.CoveredBranches);
        Assert.Equal(2, r.TotalBranches);
        var m = Assert.Single(r.Modules);
        Assert.Equal("Pkg.A", m.Name);
        Assert.Equal(3, m.CoveredSequences);      // 3 of 4 lines hit
        Assert.Equal(4, m.TotalSequences);
        Assert.Null(m.Classes);                    // no line-level overlay on the raw path
    }

    // ---- OpenCover (real fixture) --------------------------------------------------------------

    [Fact]
    public void OpenCover_reads_overall_and_rolls_up_modules()
    {
        var doc = Load(FindOpenCover());
        Assert.Equal(RawCoverageFormat.OpenCover, RawReportFormat.DetectCoverage(doc));

        var r = OpenCoverCoverageParser.Parse(doc);
        Assert.Equal("opencover", r.ToolName);
        Assert.True(r.TotalSequences > 0);
        Assert.InRange(r.SequenceCoverage, 0, 100);
        Assert.True(r.CoveredSequences <= r.TotalSequences);
        Assert.NotEmpty(r.Modules);
        // A rolled-up module never claims more covered points than it has.
        Assert.All(r.Modules, m => Assert.True(m.CoveredSequences <= m.TotalSequences));
        Assert.All(r.Modules, m => Assert.Null(m.Classes));
    }

    // ---- Hardening + sniffing ------------------------------------------------------------------

    [Fact]
    public async Task Loader_rejects_a_document_with_a_doctype_xxe()
    {
        const string xxe = """
        <?xml version="1.0"?>
        <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
        <TestRun>&xxe;</TestRun>
        """;
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(xxe));
        await Assert.ThrowsAsync<RawReportXml.MalformedException>(
            () => RawReportXml.LoadAsync(stream, default));
    }

    [Fact]
    public void Sniffers_return_null_for_an_unrecognised_root()
    {
        var doc = XDocument.Parse("<somethingElse/>");
        Assert.Null(RawReportFormat.DetectTest(doc));
        Assert.Null(RawReportFormat.DetectCoverage(doc));
    }

    // ---- helpers -------------------------------------------------------------------------------

    private static XDocument Load(string path)
    {
        using var fs = File.OpenRead(path);
        return RawReportXml.LoadAsync(fs, default).GetAwaiter().GetResult();
    }

    private static string FindTrx() => Fixture("dotnet-test.trx");
    private static string FindOpenCover() => Fixture("coverage.opencover.xml");

    private static string Fixture(string name)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !Directory.Exists(Path.Combine(dir.FullName, "src"))) dir = dir.Parent;
        Assert.NotNull(dir);
        var full = Path.Combine(dir!.FullName, "tests", "Fixtures", "Ingest", "raw", name);
        Assert.True(File.Exists(full), $"missing fixture: {full}");
        return full;
    }
}
