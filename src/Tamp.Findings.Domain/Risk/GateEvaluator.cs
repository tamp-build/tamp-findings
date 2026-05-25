namespace Tamp.Findings.Domain.Risk;

public sealed record GateResult(
    string Key,
    bool Enabled,
    bool Passed,
    // Human-readable observed value (e.g. "3 critical CVEs", "+1.4 pts",
    // "78% (prior 80%)"). Surfaced verbatim on the SPA so the evaluator
    // owns the messaging.
    string Observed,
    double? Threshold,
    string? Reason);

public sealed record GateEvaluation(
    double CurrentScore,
    double? PriorScore,         // null when this is the first canonical build
    double? DeltaPoints,
    IReadOnlyList<GateResult> Results)
{
    public int Failed => Results.Count(r => r.Enabled && !r.Passed);
    public int Passed => Results.Count(r => r.Enabled && r.Passed);
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
        GateKeys.CriticalIac,
        GateKeys.VerifiedSecrets,
        GateKeys.DeniedLicenses,
        GateKeys.TestFailures,
        GateKeys.CoverageRegression,
    ];

    private static GateResult EvaluateOne(
        string key, GateConfig cfg,
        RiskInputs current, double currentScore,
        RiskInputs? prior, double? priorScore, double? deltaPoints)
    {
        if (!cfg.Enabled)
            return new GateResult(key, false, true, "—", cfg.Threshold, null);

        return key switch
        {
            GateKeys.RiskScoreRegression => EvaluateRiskRegression(key, cfg, currentScore, priorScore, deltaPoints),
            GateKeys.KevExposure         => Threshold(key, cfg, current.KevListedCves, 0, "KEV-listed CVEs"),
            GateKeys.AnyCves             => Threshold(key, cfg, current.CveCritical + current.CveHigh + current.CveMedium + current.CveLow, 0, "open CVEs"),
            GateKeys.CriticalCves        => Threshold(key, cfg, current.CveCritical, 0, "critical CVEs"),
            GateKeys.HighCves            => Threshold(key, cfg, current.CveHigh, 0, "high CVEs"),
            GateKeys.CriticalSast        => Threshold(key, cfg, current.SastCritical, 0, "critical SAST"),
            GateKeys.CriticalIac         => Threshold(key, cfg, current.IacCritical, 0, "critical IaC misconfigs"),
            GateKeys.VerifiedSecrets     => Threshold(key, cfg, current.SecretsVerified, 0, "verified secrets"),
            GateKeys.DeniedLicenses      => Threshold(key, cfg, current.LicenseDenied, 0, "denied licenses"),
            GateKeys.TestFailures        => EvaluateTestFailures(key, cfg, current),
            GateKeys.CoverageRegression  => EvaluateCoverageRegression(key, cfg, current, prior),
            _                            => new GateResult(key, true, true, "(unknown gate)", cfg.Threshold, null),
        };
    }

    // Generic threshold gate: fail when observed > threshold (0 by default).
    private static GateResult Threshold(string key, GateConfig cfg, int observed, int defaultThreshold, string label)
    {
        var threshold = (int)(cfg.Threshold ?? defaultThreshold);
        var passed = observed <= threshold;
        var reason = passed
            ? $"{observed} {label} ≤ {threshold} allowed"
            : $"{observed} {label} exceeds {threshold} allowed";
        return new GateResult(key, true, passed, $"{observed} {label}", threshold, reason);
    }

    private static GateResult EvaluateRiskRegression(string key, GateConfig cfg, double currentScore, double? priorScore, double? delta)
    {
        if (delta is null || priorScore is null)
        {
            // First canonical build → nothing to compare against; pass.
            return new GateResult(key, true, true,
                $"{currentScore:F1}% (no prior build)", cfg.Threshold, "no prior canonical build to compare against");
        }
        var threshold = cfg.Threshold ?? 0;
        var passed = delta.Value <= threshold;
        var sign = delta.Value > 0 ? "+" : "";
        var observed = $"{sign}{delta.Value:F1} pts ({priorScore.Value:F1} → {currentScore:F1})";
        var reason = passed
            ? $"score delta {sign}{delta.Value:F1} ≤ {threshold} allowed"
            : $"score regressed by {delta.Value:F1} pts (threshold {threshold})";
        return new GateResult(key, true, passed, observed, threshold, reason);
    }

    private static GateResult EvaluateTestFailures(string key, GateConfig cfg, RiskInputs current)
    {
        if (!current.TestsMeasured)
        {
            return new GateResult(key, true, true, "no test runs", cfg.Threshold, "no test results in scope");
        }
        var threshold = (int)(cfg.Threshold ?? 0);
        var passed = current.TestsFailed <= threshold;
        var observed = $"{current.TestsFailed} failed / {current.TestsTotal} total";
        var reason = passed
            ? $"{current.TestsFailed} failures ≤ {threshold} allowed"
            : $"{current.TestsFailed} failures exceeds {threshold} allowed";
        return new GateResult(key, true, passed, observed, threshold, reason);
    }

    private static GateResult EvaluateCoverageRegression(string key, GateConfig cfg, RiskInputs current, RiskInputs? prior)
    {
        if (!current.CoverageMeasured)
        {
            return new GateResult(key, true, true, "no coverage report", cfg.Threshold, "no coverage data in scope");
        }
        if (prior is null || !prior.CoverageMeasured)
        {
            return new GateResult(key, true, true,
                $"{current.SequenceCoveragePercent:F1}% (no prior)", cfg.Threshold, "no prior canonical build with coverage");
        }
        var drop = prior.SequenceCoveragePercent - current.SequenceCoveragePercent;
        var threshold = cfg.Threshold ?? 0;
        var passed = drop <= threshold;
        var observed = $"{current.SequenceCoveragePercent:F1}% (prior {prior.SequenceCoveragePercent:F1}%)";
        var reason = passed
            ? $"coverage drop {drop:F1}pp ≤ {threshold}pp allowed"
            : $"coverage dropped {drop:F1}pp (threshold {threshold}pp)";
        return new GateResult(key, true, passed, observed, threshold, reason);
    }
}
