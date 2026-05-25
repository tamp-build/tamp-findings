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
    bool RanSast, bool RanSecrets, bool RanIac, bool RanSbom, bool RanCoverage);

public sealed record RiskCategoryBreakdown(
    string Key, bool Enabled, double Max, double SubScore, double Contribution);

public sealed record RiskResult(
    double Score,           // 0..100
    string Band,            // "green" | "yellow" | "orange" | "red"
    int SchemaVersion,
    IReadOnlyList<RiskCategoryBreakdown> Breakdown);

public static class RiskScorer
{
    public static RiskResult Compute(RiskPolicyConfig policy, RiskInputs i)
    {
        if (policy.SchemaVersion != 1)
            throw new InvalidOperationException(
                $"RiskScorer only understands SchemaVersion=1 (got {policy.SchemaVersion}).");

        var rows = new List<RiskCategoryBreakdown>();
        var total = 0.0;

        foreach (var (key, cat) in policy.Categories)
        {
            if (!cat.Enabled || cat.Max <= 0)
            {
                rows.Add(new RiskCategoryBreakdown(key, false, cat.Max, 0, 0));
                continue;
            }

            var sub = ComputeSubScore(key, cat.Weights, i);
            sub = Math.Clamp(sub, 0, 1);
            var contribution = sub * cat.Max;
            rows.Add(new RiskCategoryBreakdown(key, true, cat.Max, sub, contribution));
            total += contribution;
        }

        // Defensive clamp — a misconfigured policy that sums > 100 across
        // categories would otherwise push the score off-scale.
        total = Math.Clamp(total, 0, 100);
        return new RiskResult(total, BandFor(total, policy.Bands), policy.SchemaVersion, rows);
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

            case RiskCategoryNames.MissingScanners:
            {
                // Expected scanners we'd want to see at least one of:
                // SAST, Secrets, IaC, SBOM, Coverage.
                var expected = 5;
                var missing = 0;
                if (!i.RanSast)     missing++;
                if (!i.RanSecrets)  missing++;
                if (!i.RanIac)      missing++;
                if (!i.RanSbom)     missing++;
                if (!i.RanCoverage) missing++;
                return (double)missing / expected;
            }

            default:
                // Unknown category in the policy — skip silently. Lets new
                // categories ship in the seed without breaking existing
                // deployments mid-upgrade.
                return 0;
        }
    }

    private static string BandFor(double score, RiskBands b)
    {
        if (score <= b.GreenMax) return "green";
        if (score <= b.YellowMax) return "yellow";
        if (score <= b.OrangeMax) return "orange";
        return "red";
    }
}
