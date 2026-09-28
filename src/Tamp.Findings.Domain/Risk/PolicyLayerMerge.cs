using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Domain.Risk;

/// <summary>
/// Merges the ordered policy layers (template → client → project) into one
/// effective, hardened result (ADR 0007). Pure and deterministic — no I/O — like
/// <see cref="EnforcementResolution"/> and <see cref="GateEvaluator"/>, so an
/// effective policy recorded against a build can be reproduced later.
///
/// The rule is HARDEN-ONLY: a lower layer can only add a rule or tighten a
/// threshold; it can never loosen what an upper layer set. The merge simply
/// takes the strictest value at each field and records the layer that supplied
/// it. (Validation that a WRITE does not attempt to loosen lives in the
/// application layer; this merge just computes the strictest state.)
/// </summary>
public static class PolicyLayerMerge
{
    /// <param name="layers">
    /// The layers most-general first: <c>[template, client, project]</c>. A layer
    /// may be omitted (a client with no template, a project with no client) — pass
    /// only the layers that exist. Each entry pairs the layer with its display
    /// label, which becomes the provenance <c>Source</c>.
    /// </param>
    public static EffectivePolicyLayer Resolve(IReadOnlyList<(PolicyLayer Layer, string Source)> layers)
    {
        Sourced<EnforcementMode>? mode = null;
        var scanners = new List<Sourced<string>>();
        var gates = new Dictionary<string, EffectiveGate>();
        var denied = new List<Sourced<string>>();
        var poam = new Dictionary<string, Sourced<int>>();

        foreach (var (layer, source) in layers)
        {
            // Mode: strictest wins (Enforcing > Advisory). Ties keep the higher
            // (more general) layer's attribution — the first to set it.
            if (layer.Mode is { } m && (mode is null || (int)m > (int)mode.Value))
                mode = new Sourced<EnforcementMode>(m, source);

            // Scanners: union. First layer to require one owns the attribution.
            foreach (var s in layer.RequiredScanners)
                if (!scanners.Any(x => x.Value == s))
                    scanners.Add(new Sourced<string>(s, source));

            // Denied licences: union, first-owner attribution.
            foreach (var d in layer.DeniedLicenses)
                if (!denied.Any(x => x.Value == d))
                    denied.Add(new Sourced<string>(d, source));

            // Gates: enabled is OR; threshold is the min of provided values
            // (lower is stricter). The source is the layer that first enabled it,
            // updated to whichever layer last tightened the threshold.
            foreach (var (key, cfg) in layer.Gates)
            {
                var existing = gates.GetValueOrDefault(key);
                var enabled = (existing?.Enabled ?? false) || cfg.Enabled;

                // Choose the stricter (lower) threshold across what we have and
                // what this layer offers; null means "unset".
                var (threshold, thrSource) = StricterThreshold(
                    existing?.Threshold, existing?.Source,
                    cfg.Threshold, source);

                // Attribution: if this layer is the one that turns the gate on,
                // it owns it; otherwise keep whoever set the winning threshold,
                // falling back to the existing owner.
                string owner =
                    cfg.Enabled && (existing is null || !existing.Enabled) ? source
                    : thrSource ?? existing?.Source ?? source;

                gates[key] = new EffectiveGate(enabled, threshold, owner);
            }

            // POA&M deadlines: per severity, the min days wins (shorter is stricter).
            foreach (var (sev, days) in layer.PoamDeadlineDays)
            {
                var existing = poam.GetValueOrDefault(sev);
                if (existing is null || days < existing.Value)
                    poam[sev] = new Sourced<int>(days, source);
            }
        }

        return new EffectivePolicyLayer(mode, scanners, gates, denied, poam);
    }

    // The stricter of two thresholds. A null threshold is "unset" and loses to
    // any real value; between two values the lower wins.
    private static (double? Threshold, string? Source) StricterThreshold(
        double? a, string? aSource, double? b, string bSource)
    {
        if (b is null) return (a, aSource);
        if (a is null) return (b, bSource);
        return b.Value < a.Value ? (b, bSource) : (a, aSource);
    }
}
