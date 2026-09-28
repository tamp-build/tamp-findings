using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Domain.Risk;

/// <summary>
/// Decides whether one <see cref="PolicyLayer"/> LOOSENS another (ADR 0007) —
/// the harden-only guard. Pure and deterministic.
///
/// Used two ways:
/// <list type="bullet">
/// <item>A template save vs its own saved version — a loosening save goes to
/// InfoSec for approval ("⚠ loosened").</item>
/// <item>A client or project hardening save vs the layer it inherits — a
/// loosening save is rejected outright (a lower layer may never weaken an upper
/// one).</item>
/// </list>
/// Each loosened field is returned as a human sentence so the caller can show
/// exactly what would weaken; an empty list means the proposal only hardens or
/// leaves things equal.
/// </summary>
public static class PolicyLayerCompare
{
    /// <param name="baseline">The stricter reference (the saved template, or the inherited layer).</param>
    /// <param name="proposed">The new layer being saved.</param>
    public static IReadOnlyList<string> Loosens(PolicyLayer baseline, PolicyLayer proposed)
    {
        var loosened = new List<string>();

        // Mode: a proposal that sets a weaker mode than the baseline loosens it.
        // A null proposed mode says nothing (inherits) and cannot loosen.
        if (proposed.Mode is { } pm && baseline.Mode is { } bm && (int)pm < (int)bm)
            loosened.Add($"enforcement mode {bm} → {pm}");

        // Required scanners: dropping one the baseline requires loosens it.
        foreach (var s in baseline.RequiredScanners)
            if (!proposed.RequiredScanners.Contains(s))
                loosened.Add($"required scanner “{s}” removed");

        // Denied licences: dropping a denial loosens it.
        foreach (var d in baseline.DeniedLicenses)
            if (!proposed.DeniedLicenses.Contains(d))
                loosened.Add($"denied licence “{d}” removed");

        // Gates: turning off an enabled gate, or raising its threshold, loosens.
        foreach (var (key, bGate) in baseline.Gates)
        {
            if (!bGate.Enabled) continue;
            var pGate = proposed.Gates.GetValueOrDefault(key);
            if (pGate is null || !pGate.Enabled)
            {
                loosened.Add($"gate “{key}” turned off");
                continue;
            }
            // A higher threshold is looser (allows more before it blocks). An
            // unset (null) proposed threshold against a real baseline threshold
            // is treated as loosening — the baseline pinned a limit and the
            // proposal removes it.
            if (bGate.Threshold is { } bt && (pGate.Threshold is null || pGate.Threshold > bt))
                loosened.Add($"gate “{key}” threshold {bt} → {(pGate.Threshold?.ToString() ?? "unset")}");
        }

        // POA&M deadlines: lengthening a deadline, or dropping one, loosens.
        foreach (var (sev, bDays) in baseline.PoamDeadlineDays)
        {
            if (!proposed.PoamDeadlineDays.TryGetValue(sev, out var pDays))
                loosened.Add($"POA&M {sev} deadline removed");
            else if (pDays > bDays)
                loosened.Add($"POA&M {sev} deadline {bDays}d → {pDays}d");
        }

        return loosened;
    }

    /// <summary>True when <paramref name="proposed"/> weakens nothing in
    /// <paramref name="baseline"/> — safe to apply without approval.</summary>
    public static bool HardensOrEqual(PolicyLayer baseline, PolicyLayer proposed) =>
        Loosens(baseline, proposed).Count == 0;
}
