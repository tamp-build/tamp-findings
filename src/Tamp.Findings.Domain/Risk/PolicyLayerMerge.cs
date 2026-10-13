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
        var assertions = new Dictionary<string, EffectiveAssertion>(StringComparer.OrdinalIgnoreCase);

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

            // Control assertions (ADR 0009): per control id, the strictest kind
            // wins (Gated > Inherited > NotApplicable), gate lists union. A lower
            // layer can strengthen a control's disposition or add a new one; it
            // cannot weaken what an upper layer asserted — harden-only, same as
            // every other field here.
            foreach (var a in layer.Assertions)
            foreach (var controlId in a.ControlIds)
            {
                var existing = assertions.GetValueOrDefault(controlId);
                if (existing is null)
                {
                    assertions[controlId] = new EffectiveAssertion(
                        a.Kind, a.Gates.ToList(), a.Justification, a.InheritedFrom, source,
                        a.Overrides);
                    continue;
                }

                // Union the gate lists regardless of which kind wins — a control
                // gated by two layers is covered by the union of their gates.
                var mergedGates = existing.Gates.Concat(a.Gates).Distinct().ToList();

                // An OVERRIDING assertion wins whatever its kind (ADR 0015 §5,
                // TFND-219). This is the one place harden-only is allowed to bend, and
                // the flag is only ever set by an approved downgrade — the authoring
                // endpoint cannot set it, so reaching this branch means a second person
                // with AcceptRisk agreed and an audit entry exists. Keeping it here
                // rather than in the resolver matters: the merge stays pure and a
                // coverage result recorded against a build can still be recomputed.
                //
                // A later override beats an earlier one, for the same reason the layers
                // are ordered at all: the nearer layer is the more specific authority.
                // In practice only the project layer carries the flag.
                if (a.Overrides)
                {
                    assertions[controlId] = new EffectiveAssertion(
                        a.Kind, mergedGates, a.Justification, a.InheritedFrom, source,
                        Overridden: true);
                }
                // A non-overriding assertion cannot displace an override, even if it is
                // stricter. The downgrade was reviewed on its merits; letting the next
                // layer's generic default win would undo the decision silently, which is
                // the failure this whole path exists to avoid.
                else if (existing.Overridden)
                {
                    assertions[controlId] = existing with { Gates = mergedGates };
                }
                // Strictness ordering: lower enum value is stricter (Gated=0).
                else if ((int)a.Kind < (int)existing.Kind)
                {
                    assertions[controlId] = new EffectiveAssertion(
                        a.Kind, mergedGates, a.Justification, a.InheritedFrom, source);
                }
                // SAME KIND: the nearer layer's EXPLANATION wins (TFND-218).
                //
                // Harden-only is about the KIND, and the kind is identical here, so
                // nothing is loosened by this — only the text that explains it changes.
                // It matters because ADR 0015 §2 makes the justification carry the code
                // reference that backs the call: "the disposition is not an opinion; it
                // points at the code". Keeping the first layer's text meant a generic
                // archetype default silently displaced a project's specific evidence, so
                // promoting a library-general default into the archetype would have
                // destroyed the evidence on every project that had done the work.
                //
                // Only when the nearer layer actually HAS an explanation: a bare
                // assertion (the template's gate mappings carry gates and no prose) must
                // not blank out a real one.
                else if ((int)a.Kind == (int)existing.Kind
                      && (a.Justification is { Length: > 0 } || a.InheritedFrom is { Length: > 0 }))
                {
                    assertions[controlId] = existing with
                    {
                        Gates = mergedGates,
                        Justification = a.Justification is { Length: > 0 } ? a.Justification : existing.Justification,
                        InheritedFrom = a.InheritedFrom is { Length: > 0 } ? a.InheritedFrom : existing.InheritedFrom,
                        Source = source,
                    };
                }
                else
                {
                    assertions[controlId] = existing with { Gates = mergedGates };
                }
            }
        }

        return new EffectivePolicyLayer(mode, scanners, gates, denied, poam, assertions);
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
