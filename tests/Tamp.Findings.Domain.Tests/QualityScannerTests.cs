using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Risk;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Domain.Tests;

// Wiring the design-analysis scanners (TFND-33 … TFND-37).
//
// Spectral, Oasdiff, Stryker, NetArchTest and DependencyCruiser all had
// ScannerKind values and belonged to no set — ingested, then invisible to every
// spine and to the score. Ingesting evidence and then not showing it is the
// worst of both: the pipeline pays for the scan and nobody sees the result.
public class QualityScannerTests
{
    [Theory]
    [InlineData(ScannerKind.Spectral)]
    [InlineData(ScannerKind.Oasdiff)]
    [InlineData(ScannerKind.Stryker)]
    [InlineData(ScannerKind.NetArchTest)]
    [InlineData(ScannerKind.DependencyCruiser)]
    public void Every_design_scanner_is_in_the_quality_set(ScannerKind scanner)
    {
        Assert.Contains(scanner, ScannerKinds.Quality);
    }

    [Theory]
    [InlineData(ScannerKind.Spectral)]
    [InlineData(ScannerKind.Oasdiff)]
    [InlineData(ScannerKind.Stryker)]
    [InlineData(ScannerKind.NetArchTest)]
    [InlineData(ScannerKind.DependencyCruiser)]
    public void A_quality_scanner_is_never_treated_as_sast(ScannerKind scanner)
    {
        // THE LOAD-BEARING SEPARATION. An OpenAPI style nit reported as High
        // must never reach the criticalSast gate — a gate that fires on a lint
        // warning is a gate a team turns off, and then it is not protecting
        // them from anything.
        Assert.DoesNotContain(scanner, ScannerKinds.Sast);
    }

    [Fact]
    public void The_static_set_is_both_kinds()
    {
        // A reader asking "what did the analysis find in this file" wants both,
        // and splitting them across two screens would mean checking two.
        Assert.All(ScannerKinds.Sast, s => Assert.Contains(s, ScannerKinds.Static));
        Assert.All(ScannerKinds.Quality, s => Assert.Contains(s, ScannerKinds.Static));
    }

    [Fact]
    public void No_quality_scanner_is_dynamic()
    {
        // IsDynamic selects the request-shaped hash instead of the file/line
        // one. A design finding has a file and a line.
        Assert.All(ScannerKinds.Quality, s => Assert.False(ScannerKinds.IsDynamic(s)));
    }

    // ---- Scoring ------------------------------------------------------------

    [Fact]
    public void Quality_findings_score_under_the_federal_policy()
    {
        // The whole reason for the ticket: a scanner whose findings score
        // nothing is a scanner nobody looks at.
        var policy = RiskPolicyDefaults.BuildTampFederalV1();

        var clean = RiskScorer.Compute(policy, Clean());
        var withFindings = RiskScorer.Compute(policy, Clean() with { QualityHigh = 20 });

        Assert.True(withFindings.Score > clean.Score);
    }

    [Fact]
    public void Quality_findings_are_weighted_far_below_a_cve()
    {
        // They find WORK, not danger. Weighting them like a CVE would teach
        // people that the number is noise.
        var policy = RiskPolicyDefaults.BuildTampFederalV1();

        var oneCve = RiskScorer.Compute(policy, Clean() with { CveCritical = 1 }).Score;
        var tenQuality = RiskScorer.Compute(policy, Clean() with { QualityHigh = 10 }).Score;

        Assert.True(oneCve > tenQuality,
            $"one critical CVE ({oneCve:0.00}) should outweigh ten design findings ({tenQuality:0.00})");
    }

    [Fact]
    public void A_quality_finding_does_not_move_the_sast_categories()
    {
        // Separate buckets, separate saturation budgets.
        var policy = RiskPolicyDefaults.BuildTampFederalV1();

        var result = RiskScorer.Compute(policy, Clean() with { QualityHigh = 50 });

        var sastSevere = result.Breakdown.Single(r => r.Key == RiskCategoryNames.SastSevere);
        Assert.Equal(0, sastSevere.Contribution, precision: 8);
    }

    [Fact]
    public void The_standard_v1_policy_deliberately_omits_the_category()
    {
        // Schema 1 is a fixed 100-point budget and these weights already sum to
        // exactly 100. Adding a category would either overflow the budget or
        // take points off cve/sast/coverage — silently rescoring every project
        // on the seeded policy as a side effect of wiring five scanners.
        var standard = RiskPolicyDefaults.BuildTampStandardV1();

        Assert.DoesNotContain(RiskCategoryNames.Quality, standard.Categories.Keys);
        Assert.Equal(100, standard.Categories.Values.Where(c => c.Enabled).Sum(c => c.Max), precision: 8);
    }

    [Fact]
    public void Adding_the_category_to_the_v2_policy_redistributed_rather_than_overflowed()
    {
        // The property that made it safe to add there and not to the v1 policy.
        var federal = RiskPolicyDefaults.BuildTampFederalV1();

        var result = RiskScorer.Compute(federal, Clean());
        var total = result.Breakdown.Where(r => r.Enabled).Sum(r => r.EffectiveMax);

        Assert.Contains(RiskCategoryNames.Quality, federal.Categories.Keys);
        Assert.Equal(100, total, precision: 8);
    }

    private static RiskInputs Clean() => new(
        CveCritical: 0, CveHigh: 0, CveMedium: 0, CveLow: 0,
        KevListedCves: 0,
        SecretsVerified: 0, SecretsUnverified: 0,
        SastCritical: 0, SastHigh: 0, SastMedium: 0, SastLow: 0,
        IacCritical: 0, IacHigh: 0,
        CoverageMeasured: true, SequenceCoveragePercent: 85,
        SbomComponents: 100, SbomOutdated: 0, SbomStale: 0,
        TestsMeasured: true, TestsTotal: 500, TestsFailed: 0,
        LicenseDenied: 0, LicenseStrongCopyleft: 0, LicenseUnknown: 0,
        RanSast: true, RanSecrets: true, RanIac: true, RanSbom: true, RanCoverage: true,
        OpenPastDuePoams: 0,
        DastCritical: 0, DastHigh: 0, DastMedium: 0, DastLow: 0, RanDast: true,
        QualityHigh: 0, QualityMedium: 0, QualityLow: 0, RanQuality: true);
}
