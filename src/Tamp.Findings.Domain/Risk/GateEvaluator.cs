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
    // Everything except Pass blocks the release. The distinction between the
    // blocking verdicts is about what the reader should DO, not about whether
    // the build ships.
    public bool Blocks => Enabled && Verdict is not GateVerdict.Pass;
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

    // The release decision. Unknown and Error block alongside Fail.
    public int Blocking => Results.Count(r => r.Blocks);
    public bool ClearToShip => Blocking == 0;
}

// Pure evaluation of gates given the current build's RiskInputs +
// scores. Side-effect free; deterministic.
public static class GateEvaluator
{
    public static GateEvaluation Evaluate(
        ProjectGatesConfig config,
        RiskInputs current,
        double currentScore,
        RiskInputs? prior,
        double? priorScore)
    {
        var deltaPoints = priorScore.HasValue ? currentScore - priorScore.Value : (double?)null;
        var results = new List<GateResult>();

        foreach (var key in WellKnownGateKeys)
        {
            var gateCfg = config.Gates.TryGetValue(key, out var c) ? c : new GateConfig { Enabled = false };
            results.Add(EvaluateOne(key, gateCfg, current, currentScore, prior, priorScore, deltaPoints));
        }

        return new GateEvaluation(currentScore, priorScore, deltaPoints, results);
    }

    // Order is presentation order on the SPA — keep stable.
    private static readonly string[] WellKnownGateKeys =
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
        GateKeys.TestFailures,
        GateKeys.CoverageRegression,
        GateKeys.PoamPastDue,
    ];

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
            GateKeys.KevExposure         => Threshold(key, cfg, current.KevListedCves, 0, "KEV-listed CVEs", current.RanSbom, "SBOM"),
            GateKeys.AnyCves             => Threshold(key, cfg, current.CveCritical + current.CveHigh + current.CveMedium + current.CveLow, 0, "open CVEs", current.RanSbom, "SBOM"),
            GateKeys.CriticalCves        => Threshold(key, cfg, current.CveCritical, 0, "critical CVEs", current.RanSbom, "SBOM"),
            GateKeys.HighCves            => Threshold(key, cfg, current.CveHigh, 0, "high CVEs", current.RanSbom, "SBOM"),
            GateKeys.DeniedLicenses      => Threshold(key, cfg, current.LicenseDenied, 0, "denied licenses", current.RanSbom, "SBOM"),

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
