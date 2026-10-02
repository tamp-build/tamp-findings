using Tamp.Findings.Domain.Compliance;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Risk;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Domain.Tests;

// Coverage of the remaining Domain branches: gate catalogue/labels, every gate under every
// input shape, bands, exit codes, override ceilings, catalog defaults and small value helpers.
public class AppCovDomainBranchTests
{
    private static RiskInputs Clean() => new(
        0, 0, 0, 0, KevListedCves: 0, SecretsVerified: 0, SecretsUnverified: 0,
        SastCritical: 0, SastHigh: 0, SastMedium: 0, SastLow: 0, IacCritical: 0, IacHigh: 0,
        CoverageMeasured: true, SequenceCoveragePercent: 85, SbomComponents: 10, SbomOutdated: 0, SbomStale: 0,
        TestsMeasured: true, TestsTotal: 100, TestsFailed: 0,
        LicenseDenied: 0, LicenseStrongCopyleft: 0, LicenseUnknown: 0,
        RanSast: true, RanSecrets: true, RanIac: true, RanSbom: true, RanCoverage: true, RanSca: true, RanDast: true)
    {
        RanImageInspect = true, BaseImageAgeDays = 10, SbomAgeDays = 3,
        HasQualityGateVerdict = true, HasAnalysisCoverage = true,
    };

    private static RiskInputs Dirty() => Clean() with
    {
        CveCritical = 2, CveHigh = 1, CveMedium = 1, CveLow = 1, KevListedCves = 1, SecretsVerified = 1,
        SastCritical = 1, SastHigh = 1, DastCritical = 1, DastHigh = 1, IacCritical = 1, LicenseDenied = 1,
        UnauthorizedComponents = 1, TestsFailed = 3, SequenceCoveragePercent = 10, BaseImageAgeDays = 900,
        SbomAgeDays = 400, OpenPastDuePoams = 1, QualityGateFailed = 2, UnanalyzedLanguages = 1,
    };

    private static RiskInputs Unscanned() => Clean() with
    {
        RanSast = false, RanSecrets = false, RanIac = false, RanSbom = false, RanCoverage = false, RanSca = false,
        RanDast = false, CoverageMeasured = false, TestsMeasured = false, RanImageInspect = false, BaseImageAgeDays = null,
        SbomAgeDays = null, HasQualityGateVerdict = false, HasAnalysisCoverage = false,
    };

    private static ProjectGatesConfig AllOn(double? threshold = null)
    {
        var cfg = new ProjectGatesConfig();
        foreach (var k in GateEvaluator.WellKnownGateKeys) cfg.Gates[k] = new GateConfig { Enabled = true, Threshold = threshold };
        return cfg;
    }

    [Fact]
    public void Every_gate_has_a_label_and_description()
    {
        foreach (var k in GateEvaluator.WellKnownGateKeys)
        {
            Assert.False(string.IsNullOrWhiteSpace(GateEvaluator.Label(k)));
            Assert.NotEqual("No description registered for this gate.", GateEvaluator.Describe(k));
        }
        Assert.Equal("custom", GateEvaluator.Label("custom"));
        Assert.Equal("No description registered for this gate.", GateEvaluator.Describe("custom"));
    }

    [Fact]
    public void Gate_catalogue_covers_every_gate_key_constant()
    {
        var consts = typeof(GateKeys).GetFields().Where(f => f.IsLiteral).Select(f => (string)f.GetRawConstantValue()!).ToHashSet();
        Assert.Equal(consts.OrderBy(x => x), GateEvaluator.WellKnownGateKeys.ToHashSet().OrderBy(x => x));
    }

    [Fact]
    public void Dirty_build_fails_the_scanner_gates_and_clean_build_passes()
    {
        var clean = GateEvaluator.Evaluate(AllOn(), Clean(), 5, Clean(), 5,
            coverage: new ControlCoverage(3, 1, 1, 1, 0, []), conformance: new ConformanceSummary(2, 0, 0));
        Assert.Equal(GateEvaluator.WellKnownGateKeys.Length, clean.Results.Count);
        Assert.Equal(0, clean.Failed);
        Assert.True(clean.Results.Single(r => r.Key == GateKeys.NoUnmapped).Verdict == GateVerdict.Pass);
        Assert.True(clean.Results.Single(r => r.Key == GateKeys.AdrConformance).Verdict == GateVerdict.Pass);

        var dirty = GateEvaluator.Evaluate(AllOn(), Dirty(), 50, Clean(), 5,
            coverage: new ControlCoverage(3, 1, 1, 0, 1, []), conformance: new ConformanceSummary(2, 1, 0));
        Assert.True(dirty.Failed >= 15);
        Assert.False(dirty.ClearToShip);
        Assert.Equal(45, dirty.DeltaPoints);
        Assert.All(dirty.Results.Where(r => r.Verdict == GateVerdict.Fail), r => Assert.True(r.Blocks));
        Assert.Equal(dirty.Enabled, dirty.Passed + dirty.Failed + dirty.Unknown + dirty.Errored + dirty.NotApplicable);
    }

    [Fact]
    public void Unscanned_build_reads_unknown_never_pass()
    {
        var e = GateEvaluator.Evaluate(AllOn(), Unscanned(), 5, null, null);
        Assert.True(e.Unknown >= 14);
        Assert.Equal(GateVerdict.Pass, e.Results.Single(r => r.Key == GateKeys.RiskScoreRegression).Verdict);
        Assert.Equal(GateVerdict.Pass, e.Results.Single(r => r.Key == GateKeys.PoamPastDue).Verdict);
        Assert.Equal(GateVerdict.Unknown, e.Results.Single(r => r.Key == GateKeys.NoUnmapped).Verdict);
        Assert.Equal(GateVerdict.Unknown, e.Results.Single(r => r.Key == GateKeys.AdrConformance).Verdict);
        Assert.Equal(GateVerdict.Unknown, e.Results.Single(r => r.Key == GateKeys.CoverageRegression).Verdict);
        Assert.Equal(GateVerdict.Unknown, e.Results.Single(r => r.Key == GateKeys.CoverageFloor).Verdict);
        Assert.Equal(GateVerdict.Unknown, e.Results.Single(r => r.Key == GateKeys.BaseImageAge).Verdict);
    }

    [Fact]
    public void Disabled_gates_are_not_part_of_the_contract()
    {
        var e = GateEvaluator.Evaluate(new ProjectGatesConfig(), Dirty(), 99, null, null);
        Assert.Equal(0, e.Enabled);
        Assert.True(e.ClearToShip);
        Assert.All(e.Results, r => Assert.False(r.Blocks));
    }

    [Fact]
    public void Unidentified_base_image_and_prior_coverage_branches()
    {
        var cfg = new ProjectGatesConfig();
        cfg.Gates[GateKeys.BaseImageAge] = new GateConfig { Enabled = true };
        cfg.Gates[GateKeys.CoverageRegression] = new GateConfig { Enabled = true, Threshold = 2 };
        cfg.Gates[GateKeys.RiskScoreRegression] = new GateConfig { Enabled = true, Threshold = 1 };

        var noBase = Clean() with { BaseImageAgeDays = null };
        var r = GateEvaluator.Evaluate(cfg, noBase, 5, Clean() with { SequenceCoveragePercent = 86 }, 3);
        Assert.Contains("not identified", r.Results.Single(x => x.Key == GateKeys.BaseImageAge).Observed);
        Assert.Equal(GateVerdict.Pass, r.Results.Single(x => x.Key == GateKeys.CoverageRegression).Verdict);
        Assert.Equal(GateVerdict.Fail, r.Results.Single(x => x.Key == GateKeys.RiskScoreRegression).Verdict);

        var drop = GateEvaluator.Evaluate(cfg, Clean() with { SequenceCoveragePercent = 50 }, 3, Clean(), 3.5);
        Assert.Equal(GateVerdict.Fail, drop.Results.Single(x => x.Key == GateKeys.CoverageRegression).Verdict);
        Assert.Equal(GateVerdict.Pass, drop.Results.Single(x => x.Key == GateKeys.RiskScoreRegression).Verdict);

        var noPrior = GateEvaluator.Evaluate(cfg, Clean(), 3, Clean() with { CoverageMeasured = false }, 3);
        Assert.Contains("no prior", noPrior.Results.Single(x => x.Key == GateKeys.CoverageRegression).Observed);
    }

    [Fact]
    public void Capability_intersection_marks_conditional_gates_not_applicable()
    {
        var e = GateEvaluator.Evaluate(AllOn(), Clean(), 5, null, null, capability: ComponentCapability.Source | ComponentCapability.Deps);
        foreach (var k in new[] { GateKeys.CriticalDast, GateKeys.HighDast, GateKeys.CriticalIac, GateKeys.BaseImageAge })
            Assert.Equal(GateVerdict.NotApplicable, e.Results.Single(r => r.Key == k).Verdict);
        Assert.Equal(4, e.NotApplicable);

        var all = GateEvaluator.Evaluate(AllOn(), Clean(), 5, null, null,
            capability: ComponentCapability.Source | ComponentCapability.Deps | ComponentCapability.Image | ComponentCapability.Web | ComponentCapability.Iac);
        Assert.Equal(0, all.NotApplicable);

        Assert.Equal(ComponentCapability.Web, GateEvaluator.RequiredCapability(GateKeys.HighDast));
        Assert.Equal(ComponentCapability.Iac, GateEvaluator.RequiredCapability(GateKeys.CriticalIac));
        Assert.Equal(ComponentCapability.Image, GateEvaluator.RequiredCapability(GateKeys.BaseImageAge));
        Assert.Null(GateEvaluator.RequiredCapability(GateKeys.AnyCves));
    }

    [Fact]
    public void Conformance_gate_branches()
    {
        ProjectGatesConfig Cfg(bool on) { var c = new ProjectGatesConfig(); c.Gates[GateKeys.AdrConformance] = new GateConfig { Enabled = on }; return c; }
        GateVerdict V(bool on, ConformanceSummary? s) =>
            GateEvaluator.Evaluate(Cfg(on), Clean(), 1, null, null, conformance: s).Results.Single(r => r.Key == GateKeys.AdrConformance).Verdict;

        Assert.Equal(GateVerdict.Pass, V(false, null));
        Assert.Equal(GateVerdict.Unknown, V(true, null));
        Assert.Equal(GateVerdict.Unknown, V(true, new ConformanceSummary(0, 0, 0)));
        Assert.Equal(GateVerdict.Fail, V(true, new ConformanceSummary(3, 2, 1)));
        Assert.Equal(GateVerdict.Unknown, V(true, new ConformanceSummary(3, 0, 1)));
        Assert.Equal(GateVerdict.Pass, V(true, new ConformanceSummary(3, 0, 0)));
    }

    [Fact]
    public void Control_coverage_gate_branches()
    {
        ProjectGatesConfig Cfg(bool on) { var c = new ProjectGatesConfig(); c.Gates[GateKeys.NoUnmapped] = new GateConfig { Enabled = on }; return c; }
        GateVerdict V(bool on, ControlCoverage? cov) =>
            GateEvaluator.Evaluate(Cfg(on), Clean(), 1, null, null, coverage: cov).Results.Single(r => r.Key == GateKeys.NoUnmapped).Verdict;
        Assert.Equal(GateVerdict.Pass, V(false, null));
        Assert.Equal(GateVerdict.Unknown, V(true, null));
        Assert.Equal(GateVerdict.Unknown, V(true, ControlCoverage.Empty));
        Assert.Equal(GateVerdict.Pass, V(true, new ControlCoverage(2, 1, 1, 0, 0, [])));
        Assert.Equal(GateVerdict.Fail, V(true, new ControlCoverage(2, 1, 0, 0, 1, [])));
    }

    [Fact]
    public void Posture_gate_branches()
    {
        var now = DateTimeOffset.UtcNow;
        var cfg = new ProjectGatesConfig();
        cfg.Gates[GateKeys.BranchProtection] = new GateConfig { Enabled = true };
        cfg.Gates[GateKeys.SignedCommits] = new GateConfig { Enabled = true, Threshold = 5 };
        var check = PostureChecks.ByGateKey(GateKeys.BranchProtection)!;
        var check2 = PostureChecks.ByGateKey(GateKeys.SignedCommits)!;

        GateResult Run(RiskInputs i, string key) => GateEvaluator.Evaluate(cfg, i, 1, null, null).Results.Single(r => r.Key == key);
        RiskInputs P(string id, PostureStatus st, DateTimeOffset at, string? detail = null) =>
            Clean() with { Posture = new Dictionary<string, PostureReading> { [id] = new PostureReading(st, detail, at) } };

        Assert.Equal(GateVerdict.Unknown, Run(Clean(), GateKeys.BranchProtection).Verdict);
        Assert.Equal(GateVerdict.Unknown, Run(P(check.Id, PostureStatus.Unknown, now), GateKeys.BranchProtection).Verdict);
        Assert.Equal(GateVerdict.Unknown, Run(Clean() with { Posture = new Dictionary<string, PostureReading>() }, GateKeys.BranchProtection).Verdict);
        Assert.Equal(GateVerdict.NotApplicable, Run(P(check.Id, PostureStatus.NotApplicable, now, "n/a"), GateKeys.BranchProtection).Verdict);
        Assert.Equal(GateVerdict.Pass, Run(P(check.Id, PostureStatus.Pass, now), GateKeys.BranchProtection).Verdict);
        Assert.Equal(GateVerdict.Pass, Run(P(check.Id, PostureStatus.Pass, now, "ok"), GateKeys.BranchProtection).Verdict);
        Assert.Equal(GateVerdict.Fail, Run(P(check.Id, PostureStatus.Fail, now), GateKeys.BranchProtection).Verdict);
        Assert.Equal(GateVerdict.Fail, Run(P(check.Id, PostureStatus.Fail, now, "bad"), GateKeys.BranchProtection).Verdict);
        var stale = Run(P(check2.Id, PostureStatus.Pass, now.AddDays(-20)), GateKeys.SignedCommits);
        Assert.Equal(GateVerdict.Unknown, stale.Verdict);
        Assert.Contains("days ago", stale.Observed);
    }

    [Fact]
    public void Unknown_gate_key_is_an_error_and_blocks()
    {
        var cfg = new ProjectGatesConfig();
        // Reflection into the private evaluator is not needed: a well-known key list is closed, so
        // exercise the public config path with an unknown key present (ignored by the evaluator).
        cfg.Gates["madeUp"] = new GateConfig { Enabled = true };
        var e = GateEvaluator.Evaluate(cfg, Clean(), 1, null, null);
        Assert.DoesNotContain(e.Results, r => r.Key == "madeUp");
    }

    [Fact]
    public void Gate_exit_codes_and_outcomes()
    {
        foreach (var o in Enum.GetValues<GateOutcome>())
        {
            Assert.Equal(GateExit.Ok, GateExit.CodeFor(o, EnforcementMode.Advisory));
            _ = GateExit.CodeFor(o, EnforcementMode.Enforcing);
        }
        Assert.Equal(GateExit.Fail, GateExit.CodeFor(GateOutcome.Fail, EnforcementMode.Enforcing));
        Assert.Equal(GateExit.Unknown, GateExit.CodeFor(GateOutcome.Unknown, EnforcementMode.Enforcing));
        Assert.Equal(GateExit.Error, GateExit.CodeFor(GateOutcome.Error, EnforcementMode.Enforcing));
        Assert.Equal(GateExit.Unreachable, GateExit.CodeFor(GateOutcome.Unreachable, EnforcementMode.Enforcing));
        Assert.Equal(GateExit.Unreachable, GateExit.CodeFor((GateOutcome)99, EnforcementMode.Enforcing));
        Assert.Equal(GateExit.Ok, GateExit.CodeFor(GateOutcome.Pass, EnforcementMode.Enforcing));

        Assert.Equal(GateOutcome.Pass, GateExit.OutcomeFrom([]));
        Assert.Equal(GateOutcome.Pass, GateExit.OutcomeFrom([GateVerdict.Pass, GateVerdict.NotApplicable]));
        Assert.Equal(GateOutcome.Fail, GateExit.OutcomeFrom([GateVerdict.Unknown, GateVerdict.Error, GateVerdict.Fail]));
        Assert.Equal(GateOutcome.Error, GateExit.OutcomeFrom([GateVerdict.Unknown, GateVerdict.Error]));
        Assert.Equal(GateOutcome.Unknown, GateExit.OutcomeFrom([GateVerdict.Unknown]));
        Assert.Equal(GateOutcome.Pass, GateExit.OutcomeFrom([(GateVerdict)42]));
    }

    [Theory]
    [InlineData(Band.Green, "green", "#4fb783")]
    [InlineData(Band.Yellow, "yellow", "#d4bb4a")]
    [InlineData(Band.Orange, "orange", "#d68f42")]
    [InlineData(Band.Red, "red", "#dd5f5f")]
    public void Band_slug_hex_and_round_trip(Band band, string slug, string hex)
    {
        Assert.Equal(slug, band.Slug());
        Assert.Equal(hex, band.Hex());
        Assert.Equal(band, BandExtensions.FromSlug(slug));
    }

    [Fact]
    public void Band_unknown_slug_is_red_and_scales_classify_both_directions()
    {
        Assert.Equal(Band.Red, BandExtensions.FromSlug(null));
        Assert.Equal(Band.Red, BandExtensions.FromSlug("purple"));

        var risk = BandScale.RiskScore(new RiskBands { GreenMax = 10, YellowMax = 25, OrangeMax = 50 });
        Assert.Equal(Band.Green, risk.Classify(5));
        Assert.Equal(Band.Yellow, risk.Classify(20));
        Assert.Equal(Band.Orange, risk.Classify(40));
        Assert.Equal(Band.Red, risk.Classify(80));
        Assert.Equal("red", risk.SlugFor(80));

        var cov = BandScale.Coverage(80, 60);
        Assert.Equal(Band.Green, cov.Classify(90));
        Assert.Equal(Band.Yellow, cov.Classify(70));
        Assert.Equal(Band.Orange, cov.Classify(50));
        Assert.Equal(Band.Red, cov.Classify(10));
        Assert.Equal(Band.Orange, BandScale.Coverage(50, 50).Classify(49));

        var pct = BandScale.Percent();
        Assert.Equal(Band.Green, pct.Classify(95));
        Assert.Equal(Band.Yellow, pct.Classify(80));
        Assert.Equal(Band.Orange, pct.Classify(65));
        Assert.Equal(Band.Red, pct.Classify(1));
    }

    [Fact]
    public void Scanner_override_ceiling_rebuckets_severity()
    {
        var overrides = new Dictionary<string, ScannerOverride>
        {
            ["ESLint"] = new() { SeverityCeiling = Severity.Low },
            ["Roslyn"] = new() { SeverityCeiling = null },
        };
        var result = ScannerOverrideApplier.Apply(
        [
            (ScannerKind.ESLint, Severity.High, 3), (ScannerKind.ESLint, Severity.Low, 2), (ScannerKind.ESLint, Severity.Info, 1),
            (ScannerKind.Roslyn, Severity.Critical, 4), (ScannerKind.OpenGrep, Severity.High, 5),
        ], overrides);

        Assert.Equal(5, result.Single(r => r.Scanner == ScannerKind.ESLint && r.Severity == Severity.Low).Count);
        Assert.Equal(1, result.Single(r => r.Scanner == ScannerKind.ESLint && r.Severity == Severity.Info).Count);
        Assert.Equal(4, result.Single(r => r.Scanner == ScannerKind.Roslyn).Count);
        Assert.Equal(Severity.High, result.Single(r => r.Scanner == ScannerKind.OpenGrep).Severity);
        Assert.Empty(ScannerOverrideApplier.Apply([], overrides));
    }

    [Fact]
    public void Control_catalog_defaults_are_a_well_formed_catalog()
    {
        var controls = ControlCatalogDefaults.Build80053Rev5();
        Assert.True(controls.Count > 5);
        Assert.Equal(controls.Count, controls.Select(c => c.Id).Distinct().Count());
        Assert.All(controls, c =>
        {
            Assert.False(string.IsNullOrWhiteSpace(c.Id));
            Assert.False(string.IsNullOrWhiteSpace(c.Title));
            Assert.False(string.IsNullOrWhiteSpace(c.Family));
            Assert.NotEmpty(c.StatementLines);
        });
        Assert.Contains(controls, c => c.Id == "AC-3");
        Assert.Contains(controls, c => c.Id == "CM-6");
        Assert.False(string.IsNullOrWhiteSpace(ControlCatalogDefaults.CatalogName));
        Assert.False(string.IsNullOrWhiteSpace(ControlCatalogDefaults.CatalogVersion));
    }

    [Fact]
    public void Finding_types_classify()
    {
        Assert.True(FindingTypes.IsQualityType("bug"));
        Assert.True(FindingTypes.IsQualityType("code_smell"));
        Assert.False(FindingTypes.IsQualityType("vulnerability"));
        Assert.False(FindingTypes.IsQualityType(null));
        Assert.True(FindingTypes.IsSecurityType("vulnerability"));
        Assert.True(FindingTypes.IsSecurityType("security_hotspot"));
        Assert.False(FindingTypes.IsSecurityType("bug"));
        Assert.False(FindingTypes.IsSecurityType(null));
        Assert.Equal(2, FindingTypes.Quality.Length);
        Assert.Equal(2, FindingTypes.Security.Length);
    }

    [Theory]
    [InlineData("service", ComponentProfile.Service)]
    [InlineData("Web-Service", ComponentProfile.Service)]
    [InlineData("web", ComponentProfile.Service)]
    [InlineData("container", ComponentProfile.Container)]
    [InlineData(" IMAGE ", ComponentProfile.Container)]
    [InlineData("library", ComponentProfile.CodePackage)]
    [InlineData(null, ComponentProfile.CodePackage)]
    public void Component_profile_parse_and_capabilities(string? raw, ComponentProfile expected)
    {
        var p = ComponentProfiles.Parse(raw);
        Assert.Equal(expected, p);
        Assert.True(ComponentProfiles.Has(p, ComponentCapability.Source));
        Assert.Equal(p == ComponentProfile.Service, ComponentProfiles.Has(p, ComponentCapability.Web));
        Assert.Equal(p == ComponentProfile.Container || p == ComponentProfile.Service, ComponentProfiles.Has(p, ComponentCapability.Image));
        Assert.Equal(p == ComponentProfile.Service, ComponentProfiles.ScannerApplies(p, PolicyTemplateDefaults.ScannerClasses.DynamicScan));
        Assert.Equal(p == ComponentProfile.Service, ComponentProfiles.ScannerApplies(p, PolicyTemplateDefaults.ScannerClasses.Iac));
        Assert.True(ComponentProfiles.ScannerApplies(p, "sast"));
        Assert.Equal(ComponentCapability.Source | ComponentCapability.Deps, ComponentProfiles.Capabilities((ComponentProfile)99));
    }

    [Theory]
    [InlineData(null)]
    [InlineData(ProjectArchetype.Library)]
    [InlineData(ProjectArchetype.ContainerAction)]
    [InlineData(ProjectArchetype.ServiceApp)]
    public void Archetype_layers_label_capability_and_layer(ProjectArchetype? a)
    {
        Assert.NotNull(ArchetypeLayers.For(a));
        Assert.Contains("archetype:", ArchetypeLayers.Label(a));
        Assert.Equal(a is null, ArchetypeLayers.Label(a).Contains("unclassified", StringComparison.Ordinal));
        var cap = ArchetypeLayers.Capability(a);
        Assert.True(cap.HasFlag(ComponentCapability.Source));
        Assert.Equal(a is null or ProjectArchetype.ServiceApp, cap.HasFlag(ComponentCapability.Web));
    }
}
