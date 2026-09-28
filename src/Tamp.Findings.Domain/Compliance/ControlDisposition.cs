using Tamp.Findings.Domain.Risk;

namespace Tamp.Findings.Domain.Compliance;

// The control-disposition model (TFND-185 / ADR 0009). Every in-scope control
// resolves to exactly one disposition, computed purely from
// (in-scope controls ∩ effective assertions ∩ component capability). The
// no-unmapped meta-gate blocks when any control is Unmapped.

/// <summary>The resolved disposition of one in-scope control.</summary>
public enum ControlDisposition
{
    /// <summary>Covered by one or more automated gates.</summary>
    Gated,
    /// <summary>Satisfied by inheritance (a hosting provider / authorizing boundary).</summary>
    Inherited,
    /// <summary>Does not apply — asserted N/A, or every gate it needs a capability
    /// this build cannot produce (the TFND-184 intersection).</summary>
    NotApplicable,
    /// <summary>No assertion covers it. The gap the meta-gate blocks on.</summary>
    Unmapped,
}

/// <summary>One control's resolved disposition, for the coverage matrix.</summary>
public sealed record ControlDispositionResult(
    string ControlId,
    string Title,
    string Family,
    ControlDisposition Disposition,
    // Gate labels (Gated), the inheritance/justification text (Inherited/N/A),
    // or null (Unmapped).
    string? Detail,
    // The policy layer that supplied the winning assertion, or null (Unmapped).
    string? Source);

/// <summary>The disposition roll-up for a project's in-scope controls.</summary>
public sealed record ControlCoverage(
    int InScope,
    int Gated,
    int Inherited,
    int NotApplicable,
    int Unmapped,
    IReadOnlyList<ControlDispositionResult> Controls)
{
    /// <summary>Every in-scope control has a disposition — the mapping is complete.</summary>
    public bool Complete => Unmapped == 0;

    public static ControlCoverage Empty { get; } = new(0, 0, 0, 0, 0, []);
}

// Pure, deterministic — no I/O — like GateEvaluator and PolicyLayerMerge, so a
// coverage result recorded against a build can be recomputed later.
public static class ControlDispositionResolver
{
    /// <param name="inScopeControls">The project's baseline ∩ catalog controls.</param>
    /// <param name="assertions">The merged per-control assertions (ADR 0009).</param>
    /// <param name="capability">
    /// The build's aggregate component capability (TFND-184). When supplied, a
    /// Gated control whose gates ALL need a capability the build lacks resolves to
    /// NotApplicable ("component cannot produce this evidence") rather than Gated.
    /// Null means "assume everything applies" — the profile view, which is
    /// build-independent, passes null.
    /// </param>
    public static ControlCoverage Resolve(
        IReadOnlyList<Control> inScopeControls,
        IReadOnlyDictionary<string, EffectiveAssertion> assertions,
        ComponentCapability? capability)
    {
        var results = new List<ControlDispositionResult>(inScopeControls.Count);

        foreach (var control in inScopeControls)
        {
            var (disposition, detail, source) = ResolveOne(control.Id, assertions, capability);
            results.Add(new ControlDispositionResult(
                control.Id, control.Title, control.Family, disposition, detail, source));
        }

        return new ControlCoverage(
            InScope: results.Count,
            Gated: results.Count(r => r.Disposition == ControlDisposition.Gated),
            Inherited: results.Count(r => r.Disposition == ControlDisposition.Inherited),
            NotApplicable: results.Count(r => r.Disposition == ControlDisposition.NotApplicable),
            Unmapped: results.Count(r => r.Disposition == ControlDisposition.Unmapped),
            Controls: results);
    }

    private static (ControlDisposition, string? Detail, string? Source) ResolveOne(
        string controlId,
        IReadOnlyDictionary<string, EffectiveAssertion> assertions,
        ComponentCapability? capability)
    {
        if (!assertions.TryGetValue(controlId, out var a))
            return (ControlDisposition.Unmapped, null, null);

        switch (a.Kind)
        {
            case ControlDispositionKind.Inherited:
                return (ControlDisposition.Inherited,
                    a.InheritedFrom is { Length: > 0 } from
                        ? $"inherited from {from}" + (a.Justification is { Length: > 0 } j ? $" — {j}" : "")
                        : a.Justification,
                    a.Source);

            case ControlDispositionKind.NotApplicable:
                return (ControlDisposition.NotApplicable, a.Justification ?? "not applicable", a.Source);

            case ControlDispositionKind.Gated:
            default:
                // Capability intersection (TFND-184): if the build's capability is
                // known and EVERY gate covering this control needs a capability the
                // build lacks, the control's evidence cannot be produced here — N/A,
                // not a false "gated". A control gated by at least one applicable
                // gate stays Gated (covered by the gates that do apply).
                if (capability is { } cap && a.Gates.Count > 0
                    && a.Gates.All(g => GateEvaluator.RequiredCapability(g) is { } needed && (cap & needed) != needed))
                {
                    return (ControlDisposition.NotApplicable,
                        "n/a — component cannot produce this evidence", a.Source);
                }

                var labels = a.Gates.Count == 0
                    ? "gated"
                    : "gated by " + string.Join(", ", a.Gates.Select(GateEvaluator.Label));
                return (ControlDisposition.Gated, labels, a.Source);
        }
    }
}
