using Tamp.Findings.Domain.Compliance;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Domain.Risk;

/// <summary>
/// Makes the SCORE archetype-aware, the same way the gates already are (TFND-203).
///
/// A score category whose evidence the component cannot produce — IaC for a library, DAST or
/// accessibility for anything that isn't a running service, base-image age for anything without
/// an image — must not be scored against a ceiling it can never fill. Left in, it sits in the
/// weight basis as a permanent 0/N, quietly diluting every real category's contribution and
/// making the posture number depend on how many inapplicable buckets the policy happens to list.
///
/// The fix mirrors "disabling a category redistributes rather than deflates": an inapplicable
/// category is marked disabled, so <see cref="RiskScorer"/> drops it from the weight basis and the
/// remaining, applicable categories normalise over each other. The missing-scanners expectation is
/// narrowed the same way — a library is not penalised for never running a DAST or IaC scan.
///
/// Mutates the passed config in place; callers hand it a fresh per-request config (a jsonb
/// deserialisation or a built-in default), never a shared instance.
/// </summary>
public static class ArchetypeScoring
{
    // The capability a score category needs the component to have. Null = always applicable
    // (Source/Deps, which every archetype has).
    private static ComponentCapability? Requires(string categoryKey) => categoryKey switch
    {
        RiskCategoryNames.IacSevere => ComponentCapability.Iac,
        RiskCategoryNames.DastSevere or RiskCategoryNames.DastLow => ComponentCapability.Web,
        RiskCategoryNames.Accessibility => ComponentCapability.Web,
        RiskCategoryNames.BaseImageAge => ComponentCapability.Image,
        _ => null,
    };

    // The capability a missing-scanners expectation class needs.
    private static ComponentCapability? ScannerRequires(string scannerKey) => scannerKey switch
    {
        ExpectedScannerKeys.Iac => ComponentCapability.Iac,
        ExpectedScannerKeys.Dast => ComponentCapability.Web,
        ExpectedScannerKeys.Accessibility => ComponentCapability.Web,
        _ => null,
    };

    public static void ApplyCapability(RiskPolicyConfig config, ComponentCapability capability)
    {
        // An inapplicable category is REMOVED from this per-request config (never the stored
        // policy): the scorer's basis excludes it and the score panel does not render a phantom
        // "0.0 / 0" row for evidence the component can never produce.
        foreach (var key in config.Categories.Keys.ToArray())
        {
            if (Requires(key) is { } need && !capability.HasFlag(need))
                config.Categories.Remove(key);
        }

        // Narrow the missing-scanners expectation so a component is not marked down for a scanner
        // class it could never run. Zeroing the weight drops the class from the denominator inside
        // MissingScannersSubScore exactly as a policy that never configured it would.
        if (config.Categories.TryGetValue(RiskCategoryNames.MissingScanners, out var ms))
        {
            foreach (var scannerKey in ms.Weights.Keys.ToArray())
            {
                if (ScannerRequires(scannerKey) is { } need && !capability.HasFlag(need))
                    ms.Weights[scannerKey] = 0;
            }
        }
    }
}
