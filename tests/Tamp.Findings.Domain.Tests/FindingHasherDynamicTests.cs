using Tamp.Findings.Domain.Hashing;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Domain.Tests;

// TFND-38: dynamic-scan finding identity. The load-bearing test is
// Attack_payload_in_the_query_does_not_change_the_hash — without it, DAST
// findings never dedup across builds and open-finding counts grow forever.
public class FindingHasherDynamicTests
{
    private const string Rule = "10202";   // ZAP: anti-CSRF tokens missing

    // ------------------------------------------------------------------
    // The reason this hasher exists
    // ------------------------------------------------------------------

    [Fact]
    public void Attack_payload_in_the_query_does_not_change_the_hash()
    {
        // ZAP reports the URI it actually requested, payload included — the
        // shape is straight from ZAP's own SARIF documentation. Two scans
        // fuzzing the same parameter produce different payloads, and must
        // still be recognised as the same finding.
        var scanOne = FindingHasher.ComputeForDynamic(ScannerKind.Zap, Rule,
            "https://app.test/greeting?name=%3C%2Fp%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E");
        var scanTwo = FindingHasher.ComputeForDynamic(ScannerKind.Zap, Rule,
            "https://app.test/greeting?name=%22onmouseover%3Dalert(1)");

        Assert.Equal(scanOne, scanTwo);
    }

    [Fact]
    public void The_raw_hasher_would_have_churned_on_the_same_input()
    {
        // Documents why ComputeForDynamic exists rather than reusing Compute:
        // the static hasher keys on the path verbatim, so a payload-bearing
        // URI mints a new identity every scan.
        var a = FindingHasher.Compute(ScannerKind.Zap, Rule, "https://app.test/greeting?name=%3Cscript%3E", null);
        var b = FindingHasher.Compute(ScannerKind.Zap, Rule, "https://app.test/greeting?name=%22onmouseover", null);

        Assert.NotEqual(a, b);
    }

    // ------------------------------------------------------------------
    // What must still be distinguished
    // ------------------------------------------------------------------

    [Fact]
    public void Different_parameter_names_are_different_findings()
    {
        // Values are dropped but names are kept — two injectable parameters
        // on one route are two separate things to fix.
        var name = FindingHasher.ComputeForDynamic(ScannerKind.Zap, Rule, "https://app.test/search?name=x");
        var query = FindingHasher.ComputeForDynamic(ScannerKind.Zap, Rule, "https://app.test/search?query=x");

        Assert.NotEqual(name, query);
    }

    [Fact]
    public void Different_routes_are_different_findings()
    {
        Assert.NotEqual(
            FindingHasher.ComputeForDynamic(ScannerKind.Zap, Rule, "https://app.test/a"),
            FindingHasher.ComputeForDynamic(ScannerKind.Zap, Rule, "https://app.test/b"));
    }

    [Fact]
    public void Http_method_participates_in_identity()
    {
        // GET /orders and DELETE /orders are not the same finding.
        Assert.NotEqual(
            FindingHasher.ComputeForDynamic(ScannerKind.Zap, Rule, "https://app.test/orders", "GET"),
            FindingHasher.ComputeForDynamic(ScannerKind.Zap, Rule, "https://app.test/orders", "DELETE"));
    }

    [Fact]
    public void Method_is_case_insensitive()
    {
        Assert.Equal(
            FindingHasher.ComputeForDynamic(ScannerKind.Zap, Rule, "https://app.test/x", "post"),
            FindingHasher.ComputeForDynamic(ScannerKind.Zap, Rule, "https://app.test/x", "POST"));
    }

    [Fact]
    public void Injected_parameter_participates_in_identity()
    {
        Assert.NotEqual(
            FindingHasher.ComputeForDynamic(ScannerKind.Zap, Rule, "https://app.test/x", "GET", "userId"),
            FindingHasher.ComputeForDynamic(ScannerKind.Zap, Rule, "https://app.test/x", "GET", "orderId"));
    }

    [Fact]
    public void Different_rules_and_scanners_stay_distinct()
    {
        var zapA = FindingHasher.ComputeForDynamic(ScannerKind.Zap, "10202", "https://app.test/x");
        var zapB = FindingHasher.ComputeForDynamic(ScannerKind.Zap, "40012", "https://app.test/x");
        var nuclei = FindingHasher.ComputeForDynamic(ScannerKind.Nuclei, "10202", "https://app.test/x");

        Assert.NotEqual(zapA, zapB);
        Assert.NotEqual(zapA, nuclei);
    }

    // ------------------------------------------------------------------
    // Deliberate insensitivities
    // ------------------------------------------------------------------

    [Fact]
    public void Origin_is_excluded_so_the_same_route_matches_across_environments()
    {
        // The same weakness on the same route is one finding whether it was
        // seen on staging-7 or on a renamed ingress. Environment belongs to
        // the ComponentVersion, not to finding identity.
        Assert.Equal(
            FindingHasher.ComputeForDynamic(ScannerKind.Zap, Rule, "https://staging-7.test/greeting?name=a"),
            FindingHasher.ComputeForDynamic(ScannerKind.Zap, Rule, "https://app.example.com:8443/greeting?name=b"));
    }

    [Fact]
    public void Parameter_order_does_not_matter()
    {
        Assert.Equal(
            FindingHasher.ComputeForDynamic(ScannerKind.Zap, Rule, "https://app.test/s?b=1&a=2"),
            FindingHasher.ComputeForDynamic(ScannerKind.Zap, Rule, "https://app.test/s?a=9&b=8"));
    }

    [Fact]
    public void Repeated_parameters_collapse()
    {
        Assert.Equal(
            FindingHasher.ComputeForDynamic(ScannerKind.Zap, Rule, "https://app.test/s?a=1"),
            FindingHasher.ComputeForDynamic(ScannerKind.Zap, Rule, "https://app.test/s?a=1&a=2&a=3"));
    }

    [Fact]
    public void Fragments_are_ignored()
    {
        Assert.Equal(
            FindingHasher.ComputeForDynamic(ScannerKind.Zap, Rule, "https://app.test/s"),
            FindingHasher.ComputeForDynamic(ScannerKind.Zap, Rule, "https://app.test/s#section-2"));
    }

    [Fact]
    public void Trailing_slashes_are_ignored()
    {
        Assert.Equal(
            FindingHasher.ComputeForDynamic(ScannerKind.Zap, Rule, "https://app.test/orders"),
            FindingHasher.ComputeForDynamic(ScannerKind.Zap, Rule, "https://app.test/orders/"));
    }

    // ------------------------------------------------------------------
    // Degenerate input
    // ------------------------------------------------------------------

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Missing_url_still_hashes_deterministically(string? url)
    {
        var a = FindingHasher.ComputeForDynamic(ScannerKind.Zap, Rule, url);
        var b = FindingHasher.ComputeForDynamic(ScannerKind.Zap, Rule, url);

        Assert.Equal(a, b);
        Assert.Equal(64, a.Length);   // sha256 hex
    }

    [Fact]
    public void Relative_and_malformed_urls_are_handled_without_collapsing()
    {
        // A relative path can't go through Uri parsing, but two different
        // relative paths must not land on the same hash.
        var a = FindingHasher.ComputeForDynamic(ScannerKind.Zap, Rule, "/orders?id=1");
        var b = FindingHasher.ComputeForDynamic(ScannerKind.Zap, Rule, "/invoices?id=1");

        Assert.NotEqual(a, b);
        // and the value is still stripped
        Assert.Equal(a, FindingHasher.ComputeForDynamic(ScannerKind.Zap, Rule, "/orders?id=99999"));
    }

    [Fact]
    public void Root_path_does_not_normalise_to_empty()
    {
        var (path, _) = DastRoute.Normalize("https://app.test/");
        Assert.Equal("/", path);
    }

    [Theory]
    [InlineData("https://app.test/a/b/c?z=1&y=2", "/a/b/c", "y,z")]
    [InlineData("https://app.test/a?", "/a", "")]
    [InlineData("https://app.test/a?=novalue", "/a", "")]
    [InlineData("https://app.test/a?flag", "/a", "flag")]
    public void Url_normalisation_produces_the_expected_parts(string url, string expectedPath, string expectedParams)
    {
        var (path, names) = DastRoute.Normalize(url);
        Assert.Equal(expectedPath, path);
        Assert.Equal(expectedParams, names);
    }

    [Fact]
    public void Hash_is_stable_across_calls()
    {
        var a = FindingHasher.ComputeForDynamic(ScannerKind.Nuclei, "tech-detect", "https://app.test/x?q=1", "GET", "q");
        var b = FindingHasher.ComputeForDynamic(ScannerKind.Nuclei, "tech-detect", "https://app.test/x?q=2", "get", "q");
        Assert.Equal(a, b);
    }
}
