using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Domain.Risk;

// Snapshot of every aggregate input the scorer needs. Decouples the
// scorer from the API's AggregatesResponse DTO so the math stays in
// Domain and the API layer assembles inputs from its own shapes.
public sealed record RiskInputs(
    // CVE counts in the SBOM, summed across components in scope.
    int CveCritical, int CveHigh, int CveMedium, int CveLow,
    // Count of CVEs that are on the CISA Known Exploited Vulnerabilities
    // catalog. Subset of CveCritical+High+Medium+Low — independent
    // signal because KEV listing is binary "exploited in the wild,"
    // not a severity bucket. Used by the kevExposure gate.
    int KevListedCves,
    // Secret findings (TruffleHog: verified = live cred, unverified = match-only).
    int SecretsVerified, int SecretsUnverified,
    // SAST severities (Roslyn/ReSharper/OpenGrep/CodeQL, Code-Quality bucket).
    int SastCritical, int SastHigh, int SastMedium, int SastLow,
    // IaC severities (Trivy misconfig bucket).
    int IacCritical, int IacHigh,
    // Coverage. Measured=false means no report exists for any CV in scope.
    bool CoverageMeasured, double SequenceCoveragePercent,
    // SBOM staleness inputs.
    int SbomComponents, int SbomOutdated, int SbomStale,
    // Test results. Measured=false means no TestRunReport in scope.
    bool TestsMeasured, int TestsTotal, int TestsFailed,
    // License tier roll-up.
    int LicenseDenied, int LicenseStrongCopyleft, int LicenseUnknown,
    // Which scanners produced a Succeeded receipt in scope.
    bool RanSast, bool RanSecrets, bool RanIac, bool RanSbom, bool RanCoverage,
    // TFND-30 POA&M tracking: count of items in Open / InProgress status
    // whose ScheduledCompletionDate is in the past. Drives the
    // poamPastDue gate. RiskScorer ignores it — POA&M is a process
    // signal, not a score input.
    int OpenPastDuePoams = 0,
    // DAST severities — dynamic scan of a deployed target (ZAP / Nuclei).
    // Deliberately a separate bucket from SAST: a runtime-confirmed
    // exploit path is categorically stronger evidence than a static
    // pattern match against the same CWE, so the two shouldn't share a
    // saturation budget. Defaulted so existing construction sites — and
    // any policy that predates the dast categories — compile and score
    // unchanged.
    int DastCritical = 0, int DastHigh = 0, int DastMedium = 0, int DastLow = 0,
    bool RanDast = false,
    // TFND-33 … TFND-37 — design and maintainability findings: OpenAPI lint,
    // breaking-change detection, mutation testing, architecture rules.
    //
    // A SEPARATE bucket from SAST, and the separation is the point: an OpenAPI
    // style nit reported as High must never reach the criticalSast gate, or a
    // team learns to turn that gate off. No Critical bucket, because none of
    // these five tools finds something that stops a release on its own.
    int QualityHigh = 0, int QualityMedium = 0, int QualityLow = 0,
    bool RanQuality = false,
    // TFND-134 — how old the base image was when this build ran.
    //
    // Two flags rather than one, and the distinction is the whole point.
    // RanImageInspect says an image was inspected at all; BaseImageAgeDays is
    // null when it was, but the BASE image behind it could not be identified —
    // which is the common case, since the OCI annotation that names it is
    // usually absent. "We looked and the base is 400 days old" and "we looked
    // and cannot tell what the base is" are different answers, and neither is
    // "it is fine".
    int? BaseImageAgeDays = null,
    bool RanImageInspect = false,
    // TFND-27 — Section 508 / WCAG 2.1 AA.
    //
    // Split at axe's own line rather than at ours: axe grades violations
    // critical / serious / moderate / minor, and a "critical" there means a
    // control that cannot be operated at all by someone using a screen reader.
    // That is a blocker for federal acceptance, so it maps to the severe bucket
    // and is weighted accordingly.
    int A11ySevere = 0, int A11yModerate = 0, int A11yMinor = 0,
    bool RanAccessibility = false);

public sealed record RiskCategoryBreakdown(
    string Key,
    bool Enabled,
    // The weight exactly as authored in the policy. Under SchemaVersion 1
    // this is absolute points out of 100; under 2 it's a relative weight
    // whose scale is arbitrary (10/20/30 scores the same as 1/2/3).
    double Max,
    // Points this category can actually cost at full saturation, after
    // normalisation: 100 * Max / WeightBasis. For a well-formed v1 policy
    // (everything enabled, weights summing to 100) this equals Max. This
    // is the number worth showing an admin — it stays truthful when they
    // author weights that don't sum to anything in particular.
    double EffectiveMax,
    double SubScore,
    double Contribution,
    // True when the raw sub-score reached or passed its ceiling and was
    // clamped — more findings of this class cannot raise the score.
    //
    // Today this is exactly equivalent to SubScore == 1.0, so it is
    // strictly redundant. It exists anyway for two reasons:
    //
    //  - Re-deriving it means a caller writing `SubScore >= 1`, which is a
    //    floating-point equality test in disguise, performed far away from
    //    the arithmetic that produced the value. Here it is decided next to
    //    the clamp that creates it.
    //  - The redesign's project hub renders this fact twice on the same row
    //    — the SAT chip and the red bar fill — and the hand-off is explicit
    //    that RiskScorer should expose the breakdown per category rather
    //    than have the UI recompute it. Two independent derivations of one
    //    fact are exactly how the "9 gates enabled" contradiction happened
    //    (TFND-78).
    bool Saturated);

public sealed record RiskResult(
    double Score,           // 0..100
    string Band,            // "green" | "yellow" | "orange" | "red"
    int SchemaVersion,
    // Sum of Max across ENABLED categories. 100 for a well-formed v1
    // policy. Zero when every category is disabled — the caller should
    // treat that as "unscored" rather than "scored zero".
    double WeightBasis,
    IReadOnlyList<RiskCategoryBreakdown> Breakdown);

public static class RiskScorer
{
    // SchemaVersion 1 — fixed 100-point budget. Category.Max is absolute
    //   points; the weights are expected to sum to 100 and nothing enforces
    //   it. Disabling a category shrinks the numerator but not the implicit
    //   denominator, so turning a check OFF makes a project score BETTER.
    //
    // SchemaVersion 2 — normalised. Category.Max is a relative weight and
    //   the denominator is derived from whichever categories are enabled.
    //   Disabling a category redistributes its share across the rest
    //   instead of deflating the score, and adding a new category (dast)
    //   no longer requires stealing points from existing ones.
    //
    // The two agree exactly for a well-formed v1 policy: when every
    // category is enabled and the weights sum to 100, 100 * S / 100 == S.
    // Divergence is confined to configs that were already miscalibrated.
    public const int MaxSupportedSchemaVersion = 2;

    /// <summary>
    /// What each category's ceiling actually is under this policy, with no
    /// findings involved.
    ///
    /// The policy editor needs this to show effective maxima that move as
    /// weights change and categories are toggled — which is the whole point of
    /// that screen: A CATEGORY'S CEILING IS NOT A FIXED NUMBER. Extracted here
    /// rather than reimplemented in the editor, because a second implementation
    /// would eventually disagree with the scorer and the editor would then be
    /// demonstrating a normalisation that does not happen.
    /// </summary>
    public static IReadOnlyDictionary<string, double> EffectiveMaxima(RiskPolicyConfig policy)
    {
        var basis = WeightBasis(policy);
        var denominator = policy.SchemaVersion >= 2 ? basis : 100.0;

        var maxima = new Dictionary<string, double>(policy.Categories.Count);
        foreach (var (key, cat) in policy.Categories)
        {
            maxima[key] = !cat.Enabled || cat.Max <= 0 || denominator <= 0
                ? 0
                : 100.0 * cat.Max / denominator;
        }
        return maxima;
    }

    /// <summary>
    /// Sum of Max across ENABLED categories. This is what makes disabling a
    /// category redistribute its share rather than deflate the whole score.
    /// </summary>
    public static double WeightBasis(RiskPolicyConfig policy)
    {
        var basis = 0.0;
        foreach (var (_, cat) in policy.Categories)
        {
            if (cat.Enabled && cat.Max > 0) basis += cat.Max;
        }
        return basis;
    }

    public static RiskResult Compute(RiskPolicyConfig policy, RiskInputs i)
    {
        if (policy.SchemaVersion is < 1 or > MaxSupportedSchemaVersion)
            throw new InvalidOperationException(
                $"RiskScorer understands SchemaVersion 1..{MaxSupportedSchemaVersion} (got {policy.SchemaVersion}).");

        // Weight basis over enabled categories only — this is what makes
        // disabling a category redistribute rather than deflate.
        var basis = WeightBasis(policy);

        // The entire behavioural difference between the two schema
        // versions is this denominator.
        var denominator = policy.SchemaVersion >= 2 ? basis : 100.0;

        var rows = new List<RiskCategoryBreakdown>(policy.Categories.Count);
        var total = 0.0;

        foreach (var (key, cat) in policy.Categories)
        {
            if (!cat.Enabled || cat.Max <= 0)
            {
                // Disabled rows still render so the policy editor can show
                // the full category set with its zeroed contribution.
                rows.Add(new RiskCategoryBreakdown(key, false, cat.Max, 0, 0, 0, false));
                continue;
            }

            var effectiveMax = denominator <= 0 ? 0 : 100.0 * cat.Max / denominator;
            var raw = ComputeSubScore(key, cat.Weights, i);
            // At exactly 1.0 the category is already at its ceiling, so more
            // findings of that class cannot cost anything further. That is
            // saturation, not "one more away from it".
            var saturated = raw >= 1.0;
            var sub = Math.Clamp(raw, 0, 1);
            var contribution = sub * effectiveMax;

            rows.Add(new RiskCategoryBreakdown(key, true, cat.Max, effectiveMax, sub, contribution, saturated));
            total += contribution;
        }

        // v2 cannot exceed 100 by construction. The clamp stays because it
        // still does real work for a v1 policy whose weights sum past 100.
        total = Math.Clamp(total, 0, 100);
        return new RiskResult(total, BandFor(total, policy.Bands), policy.SchemaVersion, basis, rows);
    }

    private static double ComputeSubScore(string key, Dictionary<string, double> w, RiskInputs i)
    {
        double Get(string k, double def = 0) => w.TryGetValue(k, out var v) ? v : def;

        switch (key)
        {
            case RiskCategoryNames.Cve:
                return i.CveCritical * Get("critical")
                     + i.CveHigh     * Get("high")
                     + i.CveMedium   * Get("medium")
                     + i.CveLow      * Get("low");

            case RiskCategoryNames.Secrets:
                return i.SecretsVerified   * Get("verified")
                     + i.SecretsUnverified * Get("unverified");

            case RiskCategoryNames.SastSevere:
                return i.SastCritical * Get("critical")
                     + i.SastHigh     * Get("high");

            case RiskCategoryNames.DastSevere:
                return i.DastCritical * Get("critical")
                     + i.DastHigh     * Get("high");

            case RiskCategoryNames.Quality:
                // Severity-weighted like the other finding categories, but with
                // its own weights so an architecture violation and a critical
                // CVE are not implicitly equated. Saturates at "count × weight
                // reaches 1", the same shape as sastSevere.
                return i.QualityHigh   * Get("high")
                     + i.QualityMedium * Get("medium")
                     + i.QualityLow    * Get("low");

            case RiskCategoryNames.Accessibility:
                return i.A11ySevere   * Get("severe")
                     + i.A11yModerate * Get("moderate")
                     + i.A11yMinor    * Get("minor");

            case RiskCategoryNames.IacSevere:
                return i.IacCritical * Get("critical")
                     + i.IacHigh     * Get("high");

            case RiskCategoryNames.Coverage:
            {
                if (!i.CoverageMeasured) return Get("unmeasuredScore", 1.0);
                var target = Get("targetPercent", 80);
                if (target <= 0) return 0;
                return Math.Max(0, (target - i.SequenceCoveragePercent) / target);
            }

            case RiskCategoryNames.SbomStaleness:
            {
                if (i.SbomComponents == 0) return 0;
                var outdatedPct = (double)i.SbomOutdated / i.SbomComponents;
                var stalePct    = (double)i.SbomStale    / i.SbomComponents;
                return outdatedPct * Get("outdated")
                     + stalePct    * Get("stale");
            }

            case RiskCategoryNames.BaseImageAge:
            {
                // Unknown scores ZERO here, deliberately — the gate is where
                // "nobody looked" becomes visible, not the score. A score that
                // penalised an unmeasured base image would make every project
                // without container builds look worse than it is, and the
                // majority of projects on an instance have no image at all.
                if (i.BaseImageAgeDays is not { } age) return 0;

                // A SATURATION FRACTION in 0..1, like every other category
                // here — the category's Max carries the weight, not this.
                // Returning points instead would clamp at 1.0 and make every
                // base image past a few months score identically, which is
                // exactly the bug the ramp exists to avoid.
                var grace = Get("graceDays", 90);
                var ceiling = Get("ceilingDays", 365);

                if (age <= grace) return 0;

                // A ceiling at or below the grace period is a malformed policy.
                // Treating it as fully saturated is the safe reading: the
                // author asked for anything past grace to be as bad as it gets.
                if (ceiling <= grace) return 1;

                // Linear from grace to ceiling, then flat. Past the ceiling the
                // answer is already "replace this", and letting it keep
                // climbing would let one ancient base image swamp every other
                // category in the score.
                return Math.Min(1.0, (age - grace) / (ceiling - grace));
            }

            case RiskCategoryNames.Tests:
            {
                if (!i.TestsMeasured) return Get("unmeasuredScore", 0.5);
                if (i.TestsFailed == 0) return 0;
                if (i.TestsTotal == 0) return Get("anyFailureFloor", 0.1);
                var rate = (double)i.TestsFailed / i.TestsTotal;
                return rate * Get("failureMultiplier") + Get("anyFailureFloor");
            }

            case RiskCategoryNames.License:
            {
                var totalKnown = Math.Max(1, i.SbomComponents); // avoid div-by-zero
                var unknownPct = (double)i.LicenseUnknown / totalKnown;
                return i.LicenseDenied         * Get("denied")
                     + i.LicenseStrongCopyleft * Get("strongCopyleft")
                     + unknownPct              * Get("unknownPctMul");
            }

            case RiskCategoryNames.SastLow:
                return i.SastMedium * Get("medium")
                     + i.SastLow    * Get("low");

            case RiskCategoryNames.DastLow:
                return i.DastMedium * Get("medium")
                     + i.DastLow    * Get("low");

            case RiskCategoryNames.MissingScanners:
                return MissingScannersSubScore(w, i);

            default:
                // Unknown category in the policy — skip silently. Lets new
                // categories ship in the seed without breaking existing
                // deployments mid-upgrade.
                return 0;
        }
    }

    // Which scanner classes we expect to see for this project, and how
    // heavily each absence counts.
    //
    // v1 hardcoded five classes with equal weight, which permanently dinged
    // projects that legitimately have no such surface — a pure library has
    // no Terraform to scan, and nothing without a deployed endpoint can run
    // DAST. v2 reads the expected set from Weights: a weight > 0 means "we
    // expect this class here", 0 or absent means "not applicable".
    //
    // An empty/unconfigured bag falls back to the original five (DAST
    // excluded) so every policy authored before this change scores
    // identically.
    private static double MissingScannersSubScore(Dictionary<string, double> w, RiskInputs i)
    {
        ReadOnlySpan<(string Key, bool Ran)> expectations =
        [
            (ExpectedScannerKeys.Sast,     i.RanSast),
            (ExpectedScannerKeys.Secrets,  i.RanSecrets),
            (ExpectedScannerKeys.Iac,      i.RanIac),
            (ExpectedScannerKeys.Sbom,     i.RanSbom),
            (ExpectedScannerKeys.Coverage, i.RanCoverage),
            (ExpectedScannerKeys.Dast,     i.RanDast),
            (ExpectedScannerKeys.Accessibility, i.RanAccessibility),
        ];

        double Weight(string k) => w.TryGetValue(k, out var v) ? v : 0;

        var configured = false;
        foreach (var (key, _) in expectations)
        {
            if (Weight(key) > 0) { configured = true; break; }
        }

        double expected = 0, missing = 0;
        foreach (var (key, ran) in expectations)
        {
            // Legacy fallback reproduces the v1 five-class denominator
            // exactly: every class weighted 1 except dast, which v1 had
            // no concept of.
            // The legacy fallback reproduces the v1 five-class denominator
            // exactly: every class weighted 1 except dast and accessibility,
            // which v1 had no concept of. Adding either to the fallback would
            // retroactively penalise every project on a pre-existing policy for
            // not running a scanner nobody had asked them to run.
            var weight = configured
                ? Weight(key)
                : (key is ExpectedScannerKeys.Dast or ExpectedScannerKeys.Accessibility ? 0 : 1);

            if (weight <= 0) continue;
            expected += weight;
            if (!ran) missing += weight;
        }

        return expected <= 0 ? 0 : missing / expected;
    }

    private static string BandFor(double score, RiskBands b)
    {
        if (score <= b.GreenMax) return "green";
        if (score <= b.YellowMax) return "yellow";
        if (score <= b.OrangeMax) return "orange";
        return "red";
    }
}

// Weight keys understood by the missingScanners category. Each names a
// class of scanner rather than a specific tool, so swapping Trivy for
// Checkov doesn't change the policy.
public static class ExpectedScannerKeys
{
    public const string Sast = "sast";
    public const string Secrets = "secrets";
    public const string Iac = "iac";
    public const string Sbom = "sbom";
    public const string Coverage = "coverage";
    public const string Dast = "dast";
    // TFND-27. Absent from the legacy fallback below, so no policy authored
    // before accessibility existed suddenly starts penalising a project for not
    // running a scanner it has never heard of.
    public const string Accessibility = "accessibility";
}
