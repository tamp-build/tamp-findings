using System.Text.Json;
using Tamp.Findings.Build.Adapters;

namespace Tamp.Findings.Api.Tests;

// TFND-136. SARIF 2.1.0 §3.27.9: result.kind is notApplicable | pass | fail |
// review | open | informational, and defaults to "fail" when absent. Only
// failures are findings.
//
// axe-core reports what it CHECKED alongside what it found, so a clean page
// came back with 221 results — 164 pass, 57 notApplicable, zero failures — and
// every one was ingested as an accessibility finding. A count that says 221 when
// the scan said "0 violations found!" is the product's own thesis inverted:
// zero means nobody looked, and an inflated count sends a reader to the
// worst-looking screen on the board to find nothing there.
public class SarifResultKindFilterTests
{
    [Theory]
    [InlineData("pass")]
    [InlineData("notApplicable")]
    [InlineData("review")]
    [InlineData("open")]
    [InlineData("informational")]
    public void Non_failure_kinds_are_dropped(string kind)
    {
        var json = Sarif($$"""{"ruleId":"r","kind":"{{kind}}"}""");

        var filtered = SarifResultKindFilter.RemoveNonFailures(json, out var dropped);

        Assert.Equal(1, dropped);
        Assert.Empty(RuleIds(filtered));
    }

    [Fact]
    public void A_result_with_no_kind_is_a_failure()
    {
        // The spec default. Nearly every scanner we ingest omits the property
        // entirely, so treating absent as anything but "fail" would discard
        // almost every real finding in the pipeline.
        var filtered = SarifResultKindFilter.RemoveNonFailures(Sarif("""{"ruleId":"r"}"""), out var dropped);

        Assert.Equal(0, dropped);
        Assert.Equal(["r"], RuleIds(filtered));
    }

    [Theory]
    [InlineData("""{"ruleId":"r","kind":"fail"}""")]
    [InlineData("""{"ruleId":"r","kind":"FAIL"}""")]
    [InlineData("""{"ruleId":"r","kind":123}""")]
    [InlineData("""{"ruleId":"r","kind":null}""")]
    public void Failures_and_unrecognised_kinds_are_kept(string result)
    {
        // Unrecognised shapes are kept on purpose. Dropping a result we cannot
        // interpret is the one outcome that loses a finding silently, which is
        // the failure mode this whole filter exists to prevent.
        var filtered = SarifResultKindFilter.RemoveNonFailures(Sarif(result), out var dropped);

        Assert.Equal(0, dropped);
        Assert.Equal(["r"], RuleIds(filtered));
    }

    [Fact]
    public void Mixed_results_keep_only_the_failures()
    {
        var json = Sarif(
            """{"ruleId":"real"}""",
            """{"ruleId":"passed","kind":"pass"}""",
            """{"ruleId":"also-real","kind":"fail"}""",
            """{"ruleId":"n/a","kind":"notApplicable"}""");

        var filtered = SarifResultKindFilter.RemoveNonFailures(json, out var dropped);

        Assert.Equal(2, dropped);
        Assert.Equal(["real", "also-real"], RuleIds(filtered));
    }

    [Fact]
    public void Every_run_is_filtered_not_just_the_first()
    {
        // sast.sarif is a merge of several runs (OpenGrep plus one Roslyn run
        // per project/TFM), so stopping after run zero would leak passes from
        // every scanner but one.
        var json = """
        {"version":"2.1.0","runs":[
          {"tool":{"driver":{"name":"a"}},"results":[{"ruleId":"a1","kind":"pass"},{"ruleId":"a2"}]},
          {"tool":{"driver":{"name":"b"}},"results":[{"ruleId":"b1","kind":"pass"},{"ruleId":"b2"}]}
        ]}
        """;

        var filtered = SarifResultKindFilter.RemoveNonFailures(json, out var dropped);

        Assert.Equal(2, dropped);
        Assert.Equal(["a2", "b2"], RuleIds(filtered));
    }

    [Theory]
    [InlineData("{not json")]
    [InlineData("""{"version":"2.1.0"}""")]
    [InlineData("""{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"a"}}}]}""")]
    public void Input_it_cannot_interpret_is_returned_unchanged(string json)
    {
        // This sits in front of every SARIF the pipeline reads. A filter that
        // cannot parse something must not be the reason a scan reports nothing
        // — the parser downstream produces the better error.
        var filtered = SarifResultKindFilter.RemoveNonFailures(json, out var dropped);

        Assert.Equal(0, dropped);
        Assert.Equal(json, filtered);
    }

    // Plain concatenation, not a raw interpolated literal: the JSON's own
    // closing braces collide with the interpolation syntax and the result is
    // unreadable long before it compiles.
    private static string Sarif(params string[] results) =>
        """{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"t"}},"results":["""
        + string.Join(",", results)
        + "]}]}";

    private static List<string> RuleIds(string json)
    {
        using var doc = JsonDocument.Parse(json);
        return [.. doc.RootElement.GetProperty("runs").EnumerateArray()
            .SelectMany(r => r.TryGetProperty("results", out var res) ? res.EnumerateArray() : default)
            .Select(x => x.GetProperty("ruleId").GetString()!)];
    }
}
