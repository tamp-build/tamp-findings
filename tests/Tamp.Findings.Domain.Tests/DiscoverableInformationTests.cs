using Tamp.Findings.Domain.Risk;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Domain.Tests;

/// <summary>
/// TFND-213 / RA-5(4): what an adversary can learn about the system, classified out of the
/// findings we already hold — and the gate that blocks on the half worth blocking on.
///
/// <para>
/// The rule ids asserted here are the real ones. Several of these tests exist because the
/// live instance's ZAP data was read before the registry was written: a build there carries
/// 189 "Big Redirect Detected (Potential Sensitive Information Leak)" and 315
/// "X-Content-Type-Options Header Missing" alerts, so a gate that treated every alert
/// mentioning disclosure as blocking would have failed every web build on day one, and a
/// registry that classified header-hardening alerts would have reported noise as a
/// determination.
/// </para>
/// </summary>
public class DiscoverableInformationTests
{
    private static ExposureSignal Zap(string ruleId) =>
        new(ScannerKind.Zap, ruleId, Severity.Medium, "dast");

    private static ExposureSignal Secret(Severity severity, ScannerKind scanner = ScannerKind.TruffleHog) =>
        new(scanner, "aws-key", severity, scanner == ScannerKind.Trivy ? "secret" : null);

    [Theory]
    [InlineData("10023", ExposureClasses.DebugDiagnostics)]       // debug error messages
    [InlineData("10052", ExposureClasses.DebugDiagnostics)]       // X-ChromeLogger-Data leak
    [InlineData("10024", ExposureClasses.RequestMetadata)]        // sensitive info in URL
    [InlineData("10025", ExposureClasses.RequestMetadata)]        // referrer leak
    [InlineData("3", ExposureClasses.RequestMetadata)]            // session id in URL rewrite
    [InlineData("10045", ExposureClasses.SourceOrConfig)]         // source disclosure
    [InlineData("10062", ExposureClasses.PersonalData)]           // PII disclosure
    public void A_disclosure_alert_classifies_and_blocks(string ruleId, string expected)
    {
        var cls = ExposureClasses.Classify(Zap(ruleId));
        Assert.NotNull(cls);
        Assert.Equal(expected, cls.Id);
        Assert.Equal(ExposureTier.Disclosure, cls.Tier);
        Assert.Contains("RA-5(4)", cls.ControlRefs);
    }

    [Theory]
    [InlineData("10036", ExposureClasses.TechnologyFingerprint)]  // Server header
    [InlineData("10037", ExposureClasses.TechnologyFingerprint)]  // X-Powered-By
    [InlineData("10061", ExposureClasses.TechnologyFingerprint)]  // X-AspNet-Version
    [InlineData("2", ExposureClasses.InternalTopology)]           // private IP disclosure
    [InlineData("10027", ExposureClasses.IncidentalArtifact)]     // suspicious comments
    [InlineData("10096", ExposureClasses.IncidentalArtifact)]     // timestamp disclosure
    [InlineData("10044", ExposureClasses.IncidentalArtifact)]     // big redirect — 189 of them live
    public void A_fingerprint_alert_classifies_and_does_not_block(string ruleId, string expected)
    {
        var cls = ExposureClasses.Classify(Zap(ruleId));
        Assert.NotNull(cls);
        Assert.Equal(expected, cls.Id);
        Assert.Equal(ExposureTier.Fingerprint, cls.Tier);
    }

    [Theory]
    [InlineData("10021")]   // X-Content-Type-Options Header Missing — 315 live
    [InlineData("10055")]   // CSP directive with no fallback — 252 live
    [InlineData("10109")]   // Modern Web Application — 126 live
    [InlineData("10112")]   // Session Management Response Identified — 113 live
    [InlineData("10015")]   // Incomplete or no cache-control
    [InlineData("40018")]   // SQL injection — a real defect, but not discoverable INFORMATION
    public void An_unrelated_alert_is_not_discoverable_information(string ruleId)
    {
        // Every one of these is a finding worth acting on somewhere else. None of them is
        // something an adversary LEARNS about the system, and sweeping them in would make
        // an RA-5(4) determination a restatement of the DAST finding count.
        Assert.Null(ExposureClasses.Classify(Zap(ruleId)));
    }

    [Fact]
    public void A_verified_secret_is_a_disclosure_and_an_unverified_one_is_not()
    {
        var verified = ExposureClasses.Classify(Secret(Severity.Critical));
        Assert.Equal(ExposureClasses.LeakedCredential, verified!.Id);
        Assert.Equal(ExposureTier.Disclosure, verified.Tier);

        var candidate = ExposureClasses.Classify(Secret(Severity.High));
        Assert.Equal(ExposureClasses.CandidateCredential, candidate!.Id);
        Assert.Equal(ExposureTier.Fingerprint, candidate.Tier);

        // Trivy's secret sub-category is the same fact from a different tool; its
        // misconfiguration rows are not secrets at all.
        Assert.Equal(ExposureClasses.LeakedCredential,
            ExposureClasses.Classify(Secret(Severity.Critical, ScannerKind.Trivy))!.Id);
        Assert.Null(ExposureClasses.Classify(
            new ExposureSignal(ScannerKind.Trivy, "AVD-AWS-0001", Severity.Critical, "misconfiguration")));
    }

    [Fact]
    public void Only_scanners_in_the_filter_set_can_classify()
    {
        // The builder restricts its query to ExposureClasses.Scanners. If a scanner could
        // classify without being in that set, the gate would read a count of zero on a
        // build that had exposures — the shape of the bug ScannerKinds exists to prevent.
        foreach (var kind in Enum.GetValues<ScannerKind>())
        {
            if (ExposureClasses.Scanners.Contains(kind)) continue;
            Assert.Null(ExposureClasses.Classify(new ExposureSignal(kind, "10023", Severity.Critical, "dast")));
            Assert.Null(ExposureClasses.Classify(new ExposureSignal(kind, "anything", Severity.Critical, "secret")));
        }
    }

    [Fact]
    public void Every_class_names_the_control_it_evidences()
    {
        Assert.NotEmpty(ExposureClasses.All);
        Assert.All(ExposureClasses.All, c =>
        {
            Assert.False(string.IsNullOrWhiteSpace(c.Title));
            Assert.False(string.IsNullOrWhiteSpace(c.Description));
            Assert.Contains("RA-5(4)", c.ControlRefs);
            Assert.Same(c, ExposureClasses.ById(c.Id));
        });

        // Ids are the gate detail's keys and the roll-up's keys; a duplicate would make
        // one class silently absorb another's count.
        Assert.Equal(ExposureClasses.All.Count,
            ExposureClasses.All.Select(c => c.Id).Distinct(StringComparer.OrdinalIgnoreCase).Count());
    }

    [Fact]
    public void The_rollup_sums_by_tier_and_by_class()
    {
        var roll = ExposureClasses.Roll(
        [
            (Secret(Severity.Critical), 2),   // leaked-credential      → disclosure
            (Zap("10023"), 1),                // debug-diagnostics      → disclosure
            (Zap("10036"), 7),                // technology-fingerprint → fingerprint
            (Zap("10037"), 3),                // technology-fingerprint → fingerprint
            (Zap("10021"), 315),              // unclassified           → neither
        ]);

        Assert.Equal(3, roll.Disclosure);
        Assert.Equal(10, roll.Fingerprint);
        Assert.Equal(10, roll.ByClass[ExposureClasses.TechnologyFingerprint]);   // two alerts, one class
        Assert.False(roll.ByClass.ContainsKey("10021"));
    }

    // ---- the gate ----

    private static RiskInputs Inputs(
        int disclosure = 0, int fingerprint = 0, bool ran = true,
        IReadOnlyDictionary<string, int>? byClass = null) => new(
        0, 0, 0, 0, KevListedCves: 0,
        SecretsVerified: 0, SecretsUnverified: 0,
        SastCritical: 0, SastHigh: 0, SastMedium: 0, SastLow: 0,
        IacCritical: 0, IacHigh: 0,
        CoverageMeasured: true, SequenceCoveragePercent: 85,
        SbomComponents: 10, SbomOutdated: 0, SbomStale: 0,
        TestsMeasured: true, TestsTotal: 10, TestsFailed: 0,
        LicenseDenied: 0, LicenseStrongCopyleft: 0, LicenseUnknown: 0,
        RanSast: true, RanSecrets: true, RanIac: true, RanSbom: true, RanCoverage: true,
        DisclosureExposures: disclosure,
        FingerprintExposures: fingerprint,
        RanExposureAnalysis: ran,
        ExposuresByClass: byClass);

    private static GateResult Run(RiskInputs i, double? threshold = null)
    {
        var cfg = new ProjectGatesConfig();
        cfg.Gates[GateKeys.DiscoverableInformation] = new GateConfig { Enabled = true, Threshold = threshold };
        return GateEvaluator.Evaluate(cfg, i, 1, null, null)
            .Results.Single(r => r.Key == GateKeys.DiscoverableInformation);
    }

    [Fact]
    public void Neither_scan_having_run_is_unknown_not_a_pass()
    {
        var r = Run(Inputs(ran: false));
        Assert.Equal(GateVerdict.Unknown, r.Verdict);
        Assert.Contains("nobody looked", r.Reason!, StringComparison.Ordinal);
        Assert.True(r.Blocks);
    }

    [Fact]
    public void A_disclosure_fails_and_the_verdict_names_what_was_disclosed()
    {
        var r = Run(Inputs(disclosure: 3, byClass: new Dictionary<string, int>
        {
            [ExposureClasses.LeakedCredential] = 1,
            [ExposureClasses.DebugDiagnostics] = 2,
        }));

        Assert.Equal(GateVerdict.Fail, r.Verdict);
        // Ordered by count, so the reader is pointed at the biggest thing first.
        Assert.Matches(@"Debug and diagnostic output reachable \(2\).*Live credential disclosed \(1\)", r.Reason!);
    }

    [Fact]
    public void Fingerprints_alone_pass_but_are_still_reported()
    {
        // The half of RA-5(4) a pass/fail cannot express. A Server banner is not a reason
        // to stop a release; leaving it out of the verdict would make the determination
        // look complete when there is something to act on.
        var r = Run(Inputs(fingerprint: 10, byClass: new Dictionary<string, int>
        {
            [ExposureClasses.TechnologyFingerprint] = 10,
        }));

        Assert.Equal(GateVerdict.Pass, r.Verdict);
        Assert.False(r.Blocks);
        Assert.Contains("10 fingerprint", r.Observed, StringComparison.Ordinal);
        Assert.Contains("Technology and version identifiable (10)", r.Reason!, StringComparison.Ordinal);
    }

    [Fact]
    public void A_clean_build_says_so_plainly()
    {
        var r = Run(Inputs());
        Assert.Equal(GateVerdict.Pass, r.Verdict);
        Assert.Equal("nothing disclosed", r.Observed);
    }

    [Fact]
    public void The_threshold_is_the_number_of_disclosures_allowed()
    {
        // A dial, not a rule: a project mid-remediation can allow a known count while it
        // works them down, exactly as it can for CVEs.
        Assert.Equal(GateVerdict.Fail, Run(Inputs(disclosure: 2), threshold: 1).Verdict);
        Assert.Equal(GateVerdict.Pass, Run(Inputs(disclosure: 2), threshold: 2).Verdict);
    }

    [Fact]
    public void The_observed_text_is_ours_not_a_producers()
    {
        // TFND-215: the public report renders Observed verbatim, and a finding's own title
        // is where an internal hostname shows up. This gate composes from class titles and
        // counts, so it must never claim producer text.
        Assert.False(Run(Inputs(disclosure: 1, fingerprint: 1)).ObservedIsProducerText);
    }

    [Fact]
    public void The_gate_applies_to_every_component_capability()
    {
        // Not a Web-only gate, unlike criticalDast. A library has no deployed target and
        // still has a tree to leak a credential from, so making this conditional on the
        // Web capability would excuse the commonest exposure there is.
        Assert.Null(GateEvaluator.RequiredCapability(GateKeys.DiscoverableInformation));
    }

    [Fact]
    public void The_gate_is_offered_in_the_editor_and_described()
    {
        Assert.Contains(GateKeys.DiscoverableInformation, GateEvaluator.WellKnownGateKeys);
        Assert.Equal("Discoverable information", GateEvaluator.Label(GateKeys.DiscoverableInformation));
        Assert.DoesNotContain("No description registered",
            GateEvaluator.Describe(GateKeys.DiscoverableInformation), StringComparison.Ordinal);
    }

    [Fact]
    public void Every_federal_baseline_gates_RA_5_4_on_both_halves()
    {
        // The promotion TFND-218 deliberately deferred. RA-5(4) rested on verifiedSecrets
        // alone and lived in one project's database; it is a shipped default now, and it
        // names both gates — so a project that authored nothing claims exactly what the
        // product actually checks.
        foreach (var layer in new[]
        {
            PolicyTemplateDefaults.BuildFedRampLow(),
            PolicyTemplateDefaults.BuildFedRampModerate(),
            PolicyTemplateDefaults.BuildFedRampHigh(),
            PolicyTemplateDefaults.BuildGovRampCore(),
        })
        {
            Assert.True(layer.Gates[GateKeys.DiscoverableInformation].Enabled);

            var a = layer.Assertions.Single(x => x.ControlIds.Contains("RA-5(4)"));
            Assert.Equal(ControlDispositionKind.Gated, a.Kind);
            Assert.Contains(GateKeys.VerifiedSecrets, a.Gates);
            Assert.Contains(GateKeys.DiscoverableInformation, a.Gates);
        }
    }
}
