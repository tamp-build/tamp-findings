namespace Tamp.Findings.Domain.Risk;

// Four-valued gate verdict (ADR 0001).
//
// Two-valued logic has no way to say "I cannot answer that", and that gap was
// a real defect: a project that had never been scanned PASSED every severity
// gate, because the counts were zero and 0 <= 0. RanSast / RanDast existed on
// RiskInputs and the scorer consulted them via missingScanners, but the gates
// never did.
public enum GateVerdict
{
    // Evaluated; within threshold. Ship.
    Pass,

    // Evaluated; exceeded. Block — remedy is "go fix the finding".
    Fail,

    // Could not be evaluated, e.g. the scanner never ran. Blocks, but it is a
    // DIFFERENT problem with a different remedy: "your pipeline is not running
    // the scanner." Collapsing this into Pass was the bug; collapsing it into
    // Fail would send people hunting for findings that do not exist.
    Unknown,

    // Evaluation itself broke. Blocks, and an operator should be told.
    Error,

    // The gate does not apply to this component's capability (TFND-184): the
    // baseline required a scanner the component cannot produce (a library cannot
    // run DAST). Not run, not passed, NOT blocked — an auditable N/A, never a
    // false pass off a scan that never applied.
    NotApplicable,
}

public sealed record GateResult(
    string Key,
    bool Enabled,
    GateVerdict Verdict,
    // Human-readable observed value (e.g. "3 critical CVEs", "+1.4 pts",
    // "78% (prior 80%)"). Surfaced verbatim by the UI so the evaluator
    // owns the messaging.
    string Observed,
    double? Threshold,
    string? Reason)
{
    // Pass and NotApplicable ship; Fail/Unknown/Error block. The distinction
    // between the blocking verdicts is about what the reader should DO, not about
    // whether the build ships. NotApplicable does not block — the gate simply
    // does not apply to this component's capability (TFND-184).
    public bool Blocks => Enabled && Verdict is not (GateVerdict.Pass or GateVerdict.NotApplicable);
}

public sealed record GateEvaluation(
    double CurrentScore,
    double? PriorScore,         // null when this is the first canonical build
    double? DeltaPoints,
    IReadOnlyList<GateResult> Results)
{
    // Count of gates actually turned on. Derived here so no caller has to
    // reconstruct it — reconstructing it as Passed + Failed is what produced
    // the "9 gates enabled" line that contradicted a computed 10, and with a
    // third verdict in play that arithmetic is now wrong as well as fragile.
    public int Enabled  => Results.Count(r => r.Enabled);
    public int Passed   => Results.Count(r => r.Enabled && r.Verdict == GateVerdict.Pass);
    public int Failed   => Results.Count(r => r.Enabled && r.Verdict == GateVerdict.Fail);
    public int Unknown  => Results.Count(r => r.Enabled && r.Verdict == GateVerdict.Unknown);
    public int Errored  => Results.Count(r => r.Enabled && r.Verdict == GateVerdict.Error);
    // Enabled but not applicable to the component's capability (TFND-184).
    public int NotApplicable => Results.Count(r => r.Enabled && r.Verdict == GateVerdict.NotApplicable);

    // The release decision. Unknown and Error block alongside Fail.
    public int Blocking => Results.Count(r => r.Blocks);
    public bool ClearToShip => Blocking == 0;
}

// Pure evaluation of gates given the current build's RiskInputs +
// scores. Side-effect free; deterministic.
public static class GateEvaluator
{
    /// <param name="capability">
    /// The build's aggregate component capability (TFND-184). When supplied, a
    /// conditional gate whose required capability is absent (a DAST gate on a
    /// build with no web surface) resolves to NotApplicable rather than Unknown —
    /// the intersection rule. Null means "assume everything applies", which
    /// preserves the pre-capability behaviour for callers that do not pass it.
    /// </param>
    /// <param name="coverage">
    /// The control-disposition roll-up (TFND-185 / ADR 0009), when the
    /// no-unmapped meta-gate is in play. Null means "not computed" — an enabled
    /// noUnmapped gate then reads Unknown (no framework/catalog to check against).
    /// </param>
    public static GateEvaluation Evaluate(
        ProjectGatesConfig config,
        RiskInputs current,
        double currentScore,
        RiskInputs? prior,
        double? priorScore,
        Compliance.ComponentCapability? capability = null,
        Compliance.ControlCoverage? coverage = null,
        Compliance.ConformanceSummary? conformance = null)
    {
        var deltaPoints = priorScore.HasValue ? currentScore - priorScore.Value : (double?)null;
        var results = new List<GateResult>();

        foreach (var key in WellKnownGateKeys)
        {
            var gateCfg = config.Gates.TryGetValue(key, out var c) ? c : new GateConfig { Enabled = false };

            // The no-unmapped meta-gate reads the disposition set, not a scanner
            // count — handled separately from the count-based gates.
            if (key == GateKeys.NoUnmapped)
            {
                results.Add(EvaluateNoUnmapped(gateCfg, coverage));
                continue;
            }

            // The adrConformance meta-gate reads the review-gated conformance
            // roll-up, not a scanner count.
            if (key == GateKeys.AdrConformance)
            {
                results.Add(EvaluateAdrConformance(gateCfg, conformance));
                continue;
            }

            // Intersection rule: an enabled conditional gate the component cannot
            // produce is N/A-justified — not run, not passed, not blocked.
            if (gateCfg.Enabled && capability is { } cap
                && RequiredCapability(key) is { } needed
                && (cap & needed) != needed)
            {
                results.Add(new GateResult(key, true, GateVerdict.NotApplicable,
                    "n/a — component cannot produce this evidence", gateCfg.Threshold,
                    $"the {Label(key)} gate needs {needed} capability, which this component's profile does not have"));
                continue;
            }

            results.Add(EvaluateOne(key, gateCfg, current, currentScore, prior, priorScore, deltaPoints));
        }

        return new GateEvaluation(currentScore, priorScore, deltaPoints, results);
    }

    // The no-unmapped meta-gate (ADR 0009 §3). Pass when every in-scope control
    // has a disposition; Fail on any Unmapped; Unknown when coverage could not be
    // computed (no framework/catalog) — a gate with no controls to check is a
    // misconfiguration, not a clean build.
    private static GateResult EvaluateNoUnmapped(GateConfig cfg, Compliance.ControlCoverage? coverage)
    {
        if (!cfg.Enabled)
            return new GateResult(GateKeys.NoUnmapped, false, GateVerdict.Pass, "—", cfg.Threshold, null);

        if (coverage is null || coverage.InScope == 0)
            return new GateResult(GateKeys.NoUnmapped, true, GateVerdict.Unknown,
                "no in-scope controls", cfg.Threshold,
                "cannot evaluate control coverage: this project has no compliance framework assigned "
                + "(or no control catalog is loaded), so there are no controls to map");

        if (coverage.Complete)
            return new GateResult(GateKeys.NoUnmapped, true, GateVerdict.Pass,
                $"all {coverage.InScope} in-scope controls dispositioned", cfg.Threshold,
                $"{coverage.Gated} gated, {coverage.Inherited} inherited, {coverage.NotApplicable} n/a — 0 unmapped");

        return new GateResult(GateKeys.NoUnmapped, true, GateVerdict.Fail,
            $"{coverage.Unmapped} of {coverage.InScope} controls unmapped", cfg.Threshold,
            $"{coverage.Unmapped} in-scope controls have no disposition (gated / inherited / n/a) — "
            + "the mapping is incomplete");
    }

    // The review-gated ADR-conformance meta-gate (TFND-191 / ADR 0006). Human-first:
    // a conformance finding blocks only when undispositioned, its rule is Reviewed, and
    // (for Semantic) verify-Confirmed — all decided upstream in the summary. A build
    // with no conformance evidence reads Unknown ("nobody looked"), same discipline as
    // the scanner gates.
    private static GateResult EvaluateAdrConformance(GateConfig cfg, Compliance.ConformanceSummary? summary)
    {
        if (!cfg.Enabled)
            return new GateResult(GateKeys.AdrConformance, false, GateVerdict.Pass, "—", cfg.Threshold, null);

        if (summary is null || summary.Evaluated == 0)
            return new GateResult(GateKeys.AdrConformance, true, GateVerdict.Unknown,
                "no ADR-conformance evidence on this build", cfg.Threshold,
                "cannot evaluate ADR conformance: no conformance verdicts were ingested for this build");

        if (summary.BlockingFails > 0)
            return new GateResult(GateKeys.AdrConformance, true, GateVerdict.Fail,
                $"{summary.BlockingFails} reviewed conformance rule(s) failing", cfg.Threshold,
                $"{summary.BlockingFails} reviewed, undispositioned ADR-conformance findings contradict the code");

        if (summary.BlockingUnknowns > 0)
            return new GateResult(GateKeys.AdrConformance, true, GateVerdict.Unknown,
                $"{summary.BlockingUnknowns} reviewed conformance rule(s) unproven", cfg.Threshold,
                $"{summary.BlockingUnknowns} reviewed conformance findings could not be evaluated — a non-answer is not a pass");

        return new GateResult(GateKeys.AdrConformance, true, GateVerdict.Pass,
            $"all {summary.Evaluated} conformance verdicts clear", cfg.Threshold,
            "no reviewed, undispositioned ADR-conformance finding blocks this build");
    }

    /// <summary>The capability a conditional gate needs; null means it always
    /// applies. The single shared gate→capability map (ADR 0009): consumed by the
    /// intersection rule here and by the control-disposition resolver.</summary>
    public static Compliance.ComponentCapability? RequiredCapability(string key) => key switch
    {
        GateKeys.CriticalDast or GateKeys.HighDast => Compliance.ComponentCapability.Web,
        GateKeys.CriticalIac => Compliance.ComponentCapability.Iac,
        GateKeys.BaseImageAge => Compliance.ComponentCapability.Image,
        _ => null,
    };

    // Order is presentation order on every screen — keep stable.
    //
    // Public because the gates editor has to offer EVERY gate, including the
    // ones a project has never configured. Deriving the list from a project's
    // stored config instead would mean a gate nobody has enabled yet is a gate
    // nobody can enable.
    public static readonly string[] WellKnownGateKeys =
    [
        GateKeys.RiskScoreRegression,
        GateKeys.KevExposure,
        GateKeys.AnyCves,
        GateKeys.CriticalCves,
        GateKeys.HighCves,
        GateKeys.CriticalSast,
        GateKeys.HighSast,
        GateKeys.CriticalDast,
        GateKeys.HighDast,
        GateKeys.CriticalIac,
        GateKeys.VerifiedSecrets,
        GateKeys.DeniedLicenses,
        GateKeys.BaseImageAge,
        GateKeys.SbomAge,
        GateKeys.TestFailures,
        GateKeys.CoverageRegression,
        GateKeys.CoverageFloor,
        GateKeys.PoamPastDue,
        GateKeys.QualityGate,
        GateKeys.AnalysisCoverage,
        GateKeys.NoUnmapped,
        GateKeys.AdrConformance,
    ];

    /// <summary>
    /// The human label for a gate key.
    ///
    /// Here rather than in a component: the gate rail, the gates editor and the
    /// attestation all name the same gates, and three switch statements would
    /// eventually disagree about what one of them is called.
    /// </summary>
    public static string Label(string key) => key switch
    {
        GateKeys.RiskScoreRegression => "Risk score regression",
        GateKeys.KevExposure => "KEV exposure",
        GateKeys.AnyCves => "Any CVEs",
        GateKeys.CriticalCves => "Critical CVEs",
        GateKeys.HighCves => "High CVEs",
        GateKeys.CriticalSast => "Critical SAST",
        GateKeys.HighSast => "High SAST",
        GateKeys.CriticalDast => "Critical DAST",
        GateKeys.HighDast => "High DAST",
        GateKeys.CriticalIac => "Critical IaC",
        GateKeys.VerifiedSecrets => "Verified secrets",
        GateKeys.DeniedLicenses => "Denied licences",
        GateKeys.BaseImageAge => "Base image age",
        GateKeys.SbomAge => "SBOM age",
        GateKeys.TestFailures => "Test failures",
        GateKeys.CoverageRegression => "Coverage regression",
        GateKeys.CoverageFloor => "Coverage floor",
        GateKeys.PoamPastDue => "POA&M past due",
        GateKeys.QualityGate => "Quality gate",
        GateKeys.AnalysisCoverage => "Analysis coverage",
        GateKeys.NoUnmapped => "Control coverage",
        GateKeys.AdrConformance => "ADR conformance",
        _ => key,
    };

    /// <summary>
    /// Plain language for someone deciding whether to turn a gate on — what it
    /// blocks, and what makes it unanswerable.
    /// </summary>
    public static string Describe(string key) => key switch
    {
        GateKeys.RiskScoreRegression =>
            "Blocks when this build scores worse than the previous canonical build by more than the "
            + "threshold. The first build on a project has nothing to compare against and passes.",
        GateKeys.KevExposure =>
            "Blocks when any dependency carries a CVE on the CISA Known Exploited Vulnerabilities "
            + "list. Unanswerable without a dependency (SCA) scan.",
        GateKeys.AnyCves => "Blocks on any open CVE at all. Unanswerable without a dependency (SCA) scan.",
        GateKeys.CriticalCves => "Blocks on critical CVEs above the threshold. Needs a dependency (SCA) scan.",
        GateKeys.HighCves => "Blocks on high CVEs above the threshold. Needs a dependency (SCA) scan.",
        GateKeys.CriticalSast => "Blocks on critical static-analysis findings. Needs a SAST scan.",
        GateKeys.HighSast => "Blocks on high static-analysis findings. Needs a SAST scan.",
        GateKeys.CriticalDast =>
            "Blocks on critical findings against a running deployment. Needs a DAST scan — and a "
            + "project with no DAST receipt is unassessed, not clean.",
        GateKeys.HighDast => "Blocks on high dynamic findings. Needs a DAST scan.",
        GateKeys.CriticalIac => "Blocks on critical infrastructure misconfiguration. Needs an IaC scan.",
        GateKeys.VerifiedSecrets =>
            "Blocks on secrets a scanner verified as live. Needs a secret scan.",
        GateKeys.DeniedLicenses => "Blocks on dependencies under a denied licence tier. Needs an SBOM.",
        GateKeys.BaseImageAge =>
            "Blocks when the base image was older than the threshold on the day this was built. "
            + "Needs a container-image inspect, AND the base image to be identifiable.",
        GateKeys.TestFailures => "Blocks on failing tests. Needs an ingested test run.",
        GateKeys.CoverageRegression =>
            "Blocks when coverage drops more than the threshold against the previous build. A project "
            + "with no prior measurement has nothing to regress from and passes.",
        GateKeys.CoverageFloor =>
            "Blocks when coverage is below an absolute floor (threshold %). Unanswerable without a "
            + "coverage report — a missing measurement is not a passing one.",
        GateKeys.SbomAge =>
            "Blocks when the build's SBOM is older than the threshold in days. Under continuous "
            + "validation, stale evidence is no evidence. Unanswerable without an SBOM ingest.",
        GateKeys.PoamPastDue =>
            "Blocks on POA&M items past their committed date. UNSCHEDULED items have no date to be "
            + "past, so this gate cannot see them.",
        GateKeys.QualityGate =>
            "Blocks when the reported code-quality gate verdict (e.g. SonarQube) is FAIL. No verdict "
            + "reads Unknown, not pass — the quality SCORE counts findings, this is the process gate (SA-15).",
        GateKeys.AnalysisCoverage =>
            "Blocks when a language above the footprint threshold was left unanalyzed. \"0 findings\" only "
            + "credits static analysis (SA-11) when coverage is real; a language with no analyzer is a visible "
            + "gap, not a silent pass. Needs an analysis-coverage report.",
        GateKeys.NoUnmapped =>
            "A meta-gate: blocks when any in-scope control has no disposition (not gated, inherited "
            + "or justified N/A). It measures the coverage of the mapping itself, not any one "
            + "control. Unanswerable without a compliance framework assigned to the project.",
        GateKeys.AdrConformance =>
            "Blocks when a REVIEWED, undispositioned ADR-conformance finding contradicts the code "
            + "(a semantic verdict must be adversarially verify-confirmed first). Draft rules and "
            + "accepted deviations never block. Unanswerable without ingested conformance verdicts — "
            + "a build with none is unassessed, not clean.",
        _ => "No description registered for this gate.",
    };

    private static GateResult EvaluateOne(
        string key, GateConfig cfg,
        RiskInputs current, double currentScore,
        RiskInputs? prior, double? priorScore, double? deltaPoints)
    {
        // A disabled gate is not part of the release contract. Verdict is
        // meaningless for it; Enabled = false is what every count keys off.
        if (!cfg.Enabled)
            return new GateResult(key, false, GateVerdict.Pass, "—", cfg.Threshold, null);

        return key switch
        {
            GateKeys.RiskScoreRegression => EvaluateRiskRegression(key, cfg, currentScore, priorScore, deltaPoints),

            // CVE and licence facts come out of the SBOM pipeline. No SBOM
            // ingest means nobody looked, which is not the same as nothing
            // being there.
            // CVE/KEV gates read RanSca (an OSV/Grype scan ran), NOT RanSbom (TFND-216): an SBOM is an
            // inventory; zero CVEs from an inventory that was never scanned is unassessed, not clean.
            GateKeys.KevExposure         => Threshold(key, cfg, current.KevListedCves, 0, "KEV-listed CVEs", current.RanSca, "dependency (SCA) scan"),
            GateKeys.AnyCves             => Threshold(key, cfg, current.CveCritical + current.CveHigh + current.CveMedium + current.CveLow, 0, "open CVEs", current.RanSca, "dependency (SCA) scan"),
            GateKeys.CriticalCves        => Threshold(key, cfg, current.CveCritical, 0, "critical CVEs", current.RanSca, "dependency (SCA) scan"),
            GateKeys.HighCves            => Threshold(key, cfg, current.CveHigh, 0, "high CVEs", current.RanSca, "dependency (SCA) scan"),
            // Denied licences stay on RanSbom — that IS a property of the inventory, not a vuln scan.
            GateKeys.DeniedLicenses      => Threshold(key, cfg, current.LicenseDenied, 0, "denied licenses", current.RanSbom, "SBOM"),

            // TFND-134. Not a Threshold() call, because this gate has THREE
            // ways of not knowing rather than one, and collapsing them would
            // tell a team to fix the wrong thing.
            GateKeys.BaseImageAge        => EvaluateBaseImageAge(key, cfg, current),
            GateKeys.SbomAge             => EvaluateSbomAge(key, cfg, current),
            GateKeys.CoverageFloor       => EvaluateCoverageFloor(key, cfg, current),

            GateKeys.CriticalSast        => Threshold(key, cfg, current.SastCritical, 0, "critical SAST", current.RanSast, "SAST"),
            GateKeys.HighSast            => Threshold(key, cfg, current.SastHigh, 0, "high SAST", current.RanSast, "SAST"),
            GateKeys.CriticalDast        => Threshold(key, cfg, current.DastCritical, 0, "critical DAST", current.RanDast, "DAST"),
            GateKeys.HighDast            => Threshold(key, cfg, current.DastHigh, 0, "high DAST", current.RanDast, "DAST"),
            GateKeys.CriticalIac         => Threshold(key, cfg, current.IacCritical, 0, "critical IaC misconfigs", current.RanIac, "IaC"),
            GateKeys.VerifiedSecrets     => Threshold(key, cfg, current.SecretsVerified, 0, "verified secrets", current.RanSecrets, "secrets"),

            GateKeys.TestFailures        => EvaluateTestFailures(key, cfg, current),
            GateKeys.CoverageRegression  => EvaluateCoverageRegression(key, cfg, current, prior),

            // POA&M items are user-entered records, not scanner output, so
            // this gate is always answerable.
            GateKeys.PoamPastDue         => Threshold(key, cfg, current.OpenPastDuePoams, 0, "past-due POA&M items", true, null),
            GateKeys.QualityGate         => Threshold(key, cfg, current.QualityGateFailed, 0, "failed quality-gate conditions", current.HasQualityGateVerdict, "quality-gate verdict"),
            GateKeys.AnalysisCoverage    => Threshold(key, cfg, current.UnanalyzedLanguages, 0, "unanalyzed languages", current.HasAnalysisCoverage, "analysis-coverage report"),

            // The evaluator was handed a gate key it does not implement. That
            // is a broken configuration, not a clean build — Error, and it
            // blocks.
            _                            => new GateResult(key, true, GateVerdict.Error, "(unknown gate)", cfg.Threshold,
                                                $"no evaluator is registered for gate '{key}'"),
        };
    }

    // Generic threshold gate: fail when observed > threshold (0 by default).
    //
    // `ran` is what keeps this honest. When the scanner that produces `observed`
    // never ran, `observed` is zero because nobody looked — and 0 <= threshold
    // would read as a pass. That was the defect ADR 0001 was written around.
    private static GateResult Threshold(
        string key, GateConfig cfg, int observed, int defaultThreshold, string label,
        bool ran, string? scanner)
    {
        var threshold = (int)(cfg.Threshold ?? defaultThreshold);

        if (!ran)
            return new GateResult(key, true, GateVerdict.Unknown,
                $"no {scanner} scan on this build", threshold,
                $"cannot evaluate {label}: no {scanner} scan ran, so a count of zero means nobody looked");

        var verdict = observed <= threshold ? GateVerdict.Pass : GateVerdict.Fail;
        var reason = verdict == GateVerdict.Pass
            ? $"{observed} {label} ≤ {threshold} allowed"
            : $"{observed} {label} exceeds {threshold} allowed";
        return new GateResult(key, true, verdict, $"{observed} {label}", threshold, reason);
    }

    /// <summary>
    /// How old the base image was on the day this was built (TFND-134).
    ///
    /// Three distinct ways of not knowing, and they are reported separately
    /// because they call for three different actions:
    ///
    ///  1. No image was inspected — add the inspect step to the pipeline.
    ///  2. An image was inspected but the BASE could not be identified — name
    ///     the base image in the build script. This is the common one: the OCI
    ///     annotation that carries it is usually absent.
    ///  3. The base was identified but publishes no timestamp — nothing to do;
    ///     some reproducible builds zero that field.
    ///
    /// All three are Unknown rather than Pass. An unmeasured base image is not
    /// a fresh one, and this is the same rule as every other gate here.
    /// </summary>
    private static GateResult EvaluateBaseImageAge(string key, GateConfig cfg, RiskInputs current)
    {
        var threshold = (int)(cfg.Threshold ?? 365);

        if (!current.RanImageInspect)
        {
            return new GateResult(key, true, GateVerdict.Unknown,
                "no image inspected on this build", threshold,
                "cannot evaluate base image age: no container image was inspected, so an age of "
                + "zero would mean nobody looked");
        }

        if (current.BaseImageAgeDays is not { } age)
        {
            return new GateResult(key, true, GateVerdict.Unknown,
                "base image not identified", threshold,
                "an image was inspected but its base image could not be identified. Name the base "
                + "image in the build so it can be inspected too — guessing it from layer history "
                + "would be a confident wrong answer");
        }

        var verdict = age <= threshold ? GateVerdict.Pass : GateVerdict.Fail;
        var reason = verdict == GateVerdict.Pass
            ? $"base image was {age} days old at build, within {threshold} allowed"
            : $"base image was {age} days old at build, over the {threshold} allowed";

        return new GateResult(key, true, verdict, $"{age} days old at build", threshold, reason);
    }

    // TFND-182. The SBOM's own age (now minus when it was ingested). A missing
    // SBOM is Unknown, not a fresh one — the same "absent evidence is not clean
    // evidence" discipline as the scan gates.
    private static GateResult EvaluateSbomAge(string key, GateConfig cfg, RiskInputs current)
    {
        var threshold = (int)(cfg.Threshold ?? 30);
        if (!current.RanSbom || current.SbomAgeDays is not { } age)
            return new GateResult(key, true, GateVerdict.Unknown, "no SBOM", threshold,
                "cannot evaluate SBOM age: no SBOM was ingested for this build — a missing SBOM is not a fresh one");

        var passed = age <= threshold;
        var reason = passed
            ? $"SBOM is {age} days old, within {threshold} allowed"
            : $"SBOM is {age} days old, over the {threshold} allowed — refresh it";
        return new GateResult(key, true, passed ? GateVerdict.Pass : GateVerdict.Fail, $"{age} days old", threshold, reason);
    }

    // TFND-182. An absolute coverage floor. Unmeasured is Unknown (a missing
    // report is not a passing one), NOT a fabricated pass.
    private static GateResult EvaluateCoverageFloor(string key, GateConfig cfg, RiskInputs current)
    {
        var threshold = cfg.Threshold ?? 0;
        if (!current.CoverageMeasured)
            return new GateResult(key, true, GateVerdict.Unknown, "no coverage report", threshold,
                "cannot evaluate a coverage floor: no coverage report was ingested for this build");

        var passed = current.SequenceCoveragePercent >= threshold;
        var observed = $"{current.SequenceCoveragePercent:F1}%";
        var reason = passed
            ? $"coverage {current.SequenceCoveragePercent:F1}% ≥ {threshold}% floor"
            : $"coverage {current.SequenceCoveragePercent:F1}% below the {threshold}% floor";
        return new GateResult(key, true, passed ? GateVerdict.Pass : GateVerdict.Fail, observed, threshold, reason);
    }

    private static GateResult EvaluateRiskRegression(string key, GateConfig cfg, double currentScore, double? priorScore, double? delta)
    {
        if (delta is null || priorScore is null)
        {
            // First canonical build. This is a PASS, not an Unknown: the
            // question "did the score regress?" has a real answer, and it is
            // no — there is nothing to have regressed from. Unknown is for
            // "nobody measured", and would block every brand-new project on
            // its first build forever, which is not a pipeline defect to fix.
            return new GateResult(key, true, GateVerdict.Pass,
                $"{currentScore:F1}% (no prior build)", cfg.Threshold, "no prior canonical build to compare against");
        }
        var threshold = cfg.Threshold ?? 0;
        var passed = delta.Value <= threshold;
        var sign = delta.Value > 0 ? "+" : "";
        var observed = $"{sign}{delta.Value:F1} pts ({priorScore.Value:F1} → {currentScore:F1})";
        var reason = passed
            ? $"score delta {sign}{delta.Value:F1} ≤ {threshold} allowed"
            : $"score regressed by {delta.Value:F1} pts (threshold {threshold})";
        return new GateResult(key, true, passed ? GateVerdict.Pass : GateVerdict.Fail, observed, threshold, reason);
    }

    private static GateResult EvaluateTestFailures(string key, GateConfig cfg, RiskInputs current)
    {
        if (!current.TestsMeasured)
        {
            // A suite that never ran is not a passing suite. This is the same
            // defect class as SSDF PW.8.1 answering "Yes" off a green test run
            // that did not exist (fixed under TFND-38).
            return new GateResult(key, true, GateVerdict.Unknown, "no test runs", cfg.Threshold,
                "cannot evaluate test failures: no test results were ingested for this build");
        }
        var threshold = (int)(cfg.Threshold ?? 0);
        var passed = current.TestsFailed <= threshold;
        var observed = $"{current.TestsFailed} failed / {current.TestsTotal} total";
        var reason = passed
            ? $"{current.TestsFailed} failures ≤ {threshold} allowed"
            : $"{current.TestsFailed} failures exceeds {threshold} allowed";
        return new GateResult(key, true, passed ? GateVerdict.Pass : GateVerdict.Fail, observed, threshold, reason);
    }

    private static GateResult EvaluateCoverageRegression(string key, GateConfig cfg, RiskInputs current, RiskInputs? prior)
    {
        if (!current.CoverageMeasured)
        {
            // Nobody measured coverage on this build, so there is no figure to
            // compare and "it did not drop" would be a fabrication.
            return new GateResult(key, true, GateVerdict.Unknown, "no coverage report", cfg.Threshold,
                "cannot evaluate coverage regression: no coverage report was ingested for this build");
        }
        if (prior is null || !prior.CoverageMeasured)
        {
            // Coverage IS measured here; there is simply nothing earlier to
            // compare against. Same reasoning as the first-build case on
            // riskScoreRegression: a real answer, and it is "no regression".
            return new GateResult(key, true, GateVerdict.Pass,
                $"{current.SequenceCoveragePercent:F1}% (no prior)", cfg.Threshold, "no prior canonical build with coverage");
        }
        var drop = prior.SequenceCoveragePercent - current.SequenceCoveragePercent;
        var threshold = cfg.Threshold ?? 0;
        var passed = drop <= threshold;
        var observed = $"{current.SequenceCoveragePercent:F1}% (prior {prior.SequenceCoveragePercent:F1}%)";
        var reason = passed
            ? $"coverage drop {drop:F1}pp ≤ {threshold}pp allowed"
            : $"coverage dropped {drop:F1}pp (threshold {threshold}pp)";
        return new GateResult(key, true, passed ? GateVerdict.Pass : GateVerdict.Fail, observed, threshold, reason);
    }
}
