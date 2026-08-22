using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Domain.Tests;

// These sets decide three things that must agree: which hash a finding gets
// at ingest, which risk bucket it scores into, and which browse surface shows
// it. They used to be duplicated per call site, which is how a scanner ends up
// scored correctly and hashed wrongly — findings that look right and churn
// silently. Consolidated in TFND-38; these tests pin the membership.
public class ScannerKindsTests
{
    [Theory]
    [InlineData(ScannerKind.Zap)]
    [InlineData(ScannerKind.Nuclei)]
    public void Dynamic_scanners_select_the_dynamic_hasher(ScannerKind scanner)
    {
        Assert.True(ScannerKinds.IsDynamic(scanner));
        Assert.Contains(scanner, ScannerKinds.Dast);
    }

    [Theory]
    [InlineData(ScannerKind.Roslyn)]
    [InlineData(ScannerKind.ReSharper)]
    [InlineData(ScannerKind.OpenGrep)]
    [InlineData(ScannerKind.CodeQL)]
    [InlineData(ScannerKind.ESLint)]
    public void Static_scanners_do_not(ScannerKind scanner)
    {
        Assert.False(ScannerKinds.IsDynamic(scanner));
        Assert.Contains(scanner, ScannerKinds.Sast);
    }

    [Theory]
    [InlineData(ScannerKind.Trivy)]       // IaC + secrets, own buckets
    [InlineData(ScannerKind.TruffleHog)]  // secrets
    [InlineData(ScannerKind.AxeCore)]     // dynamic, but accessibility not security
    [InlineData(ScannerKind.OsvScanner)]  // SCA
    [InlineData(ScannerKind.Unknown)]
    public void Scanners_in_neither_bucket_stay_out_of_both(ScannerKind scanner)
    {
        Assert.False(ScannerKinds.IsDynamic(scanner));
        Assert.DoesNotContain(scanner, ScannerKinds.Sast);
        Assert.DoesNotContain(scanner, ScannerKinds.Dast);
    }

    [Fact]
    public void Sast_and_dast_are_disjoint()
    {
        // A scanner in both would be double-counted by the risk scorer.
        Assert.Empty(ScannerKinds.Sast.Intersect(ScannerKinds.Dast));
    }

    [Fact]
    public void AxeCore_is_deliberately_excluded_from_dast()
    {
        // axe-core scans a deployed URL, so it looks dynamic — but it reports
        // accessibility, not security. Folding it into Dast would let a11y
        // findings trip the criticalDast gate and satisfy SSDF PW.8.1, which
        // asks for dynamic *security* analysis.
        Assert.DoesNotContain(ScannerKind.AxeCore, ScannerKinds.Dast);
    }
}
