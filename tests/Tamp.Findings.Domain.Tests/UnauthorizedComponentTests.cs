using Tamp.Findings.Domain.Risk;

namespace Tamp.Findings.Domain.Tests;

// TFND-211 / CM-8(3): the unauthorized-component gate and the purl matching it relies on.
public class UnauthorizedComponentTests
{
    private static ProjectGatesConfig Gate()
    {
        var cfg = new ProjectGatesConfig();
        cfg.Gates[GateKeys.UnauthorizedComponent] = new GateConfig { Enabled = true, Threshold = 0 };
        return cfg;
    }

    private static RiskInputs Inputs(int unauthorized, bool ranSbom = true) => new(
        0, 0, 0, 0, KevListedCves: 0,
        SecretsVerified: 0, SecretsUnverified: 0,
        SastCritical: 0, SastHigh: 0, SastMedium: 0, SastLow: 0,
        IacCritical: 0, IacHigh: 0,
        CoverageMeasured: true, SequenceCoveragePercent: 85,
        SbomComponents: 10, SbomOutdated: 0, SbomStale: 0,
        TestsMeasured: true, TestsTotal: 100, TestsFailed: 0,
        LicenseDenied: 0, LicenseStrongCopyleft: 0, LicenseUnknown: 0,
        RanSast: true, RanSecrets: true, RanIac: true, RanSbom: ranSbom, RanCoverage: true, RanSca: true,
        RanDast: true, UnauthorizedComponents: unauthorized);

    private static GateResult Run(RiskInputs i) =>
        GateEvaluator.Evaluate(Gate(), i, 1, null, null).Results.Single(r => r.Key == GateKeys.UnauthorizedComponent);

    [Fact]
    public void A_banned_component_in_the_sbom_fails_the_gate()
    {
        var r = Run(Inputs(unauthorized: 2));
        Assert.Equal(GateVerdict.Fail, r.Verdict);
        Assert.Contains("2 unauthorized components", r.Observed);
    }

    [Fact]
    public void A_clean_sbom_passes()
    {
        Assert.Equal(GateVerdict.Pass, Run(Inputs(0)).Verdict);
    }

    [Fact]
    public void No_sbom_is_unknown_not_clean()
    {
        Assert.Equal(GateVerdict.Unknown, Run(Inputs(0, ranSbom: false)).Verdict);
    }

    [Fact]
    public void The_gate_has_a_label_a_description_and_is_in_the_well_known_set()
    {
        Assert.Contains(GateKeys.UnauthorizedComponent, GateEvaluator.WellKnownGateKeys);
        Assert.Equal("Unauthorized components", GateEvaluator.Label(GateKeys.UnauthorizedComponent));
        Assert.DoesNotContain("No description registered", GateEvaluator.Describe(GateKeys.UnauthorizedComponent));
    }

    [Theory]
    [InlineData("pkg:npm/Evil-Pkg@1.2.3", "pkg:npm/evil-pkg")]
    [InlineData("pkg:nuget/Bunifu.Form@8.3.53?type=x#sub", "pkg:nuget/bunifu.form")]
    [InlineData("pkg:npm/%40scope/Name@1.0.0", "pkg:npm/@scope/name")]
    [InlineData("pkg:nuget/NoVersion", "pkg:nuget/noversion")]
    public void Key_strips_version_qualifiers_and_case(string purl, string expected) =>
        Assert.Equal(expected, BannedComponentMatcher.Key(purl));

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("left-pad")]
    [InlineData("https://example.com/pkg")]
    public void Key_rejects_things_that_are_not_purls(string input) =>
        Assert.Null(BannedComponentMatcher.Key(input));

    [Fact]
    public void An_entry_with_no_versions_bans_every_version_and_one_with_versions_only_those()
    {
        Assert.True(BannedComponentMatcher.VersionMatches([], "9.9.9"));
        Assert.True(BannedComponentMatcher.VersionMatches(["1.0.0", "1.0.1"], "1.0.1"));
        Assert.False(BannedComponentMatcher.VersionMatches(["1.0.0"], "2.0.0"));
        Assert.False(BannedComponentMatcher.VersionMatches(["1.0.0"], null));
    }
}
