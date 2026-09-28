using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Domain.Risk;

/// <summary>
/// The hardenable overlay carried by ONE layer of the three-layer policy
/// (template → client → project; ADR 0007). Orthogonal to <see cref="RiskPolicy"/>
/// scoring weights and bands, which stay in <c>RiskPolicyConfig</c>: a layer
/// hardens WHAT BLOCKS a build, not how the score is computed.
///
/// Every field is "add or tighten only" when a lower layer sets it — the merge
/// (<see cref="PolicyLayerMerge"/>) takes the strictest value across layers and
/// records which layer supplied it. A null / empty field means "this layer says
/// nothing; inherit from above".
///
/// Stored as jsonb (like <see cref="ProjectGatesConfig"/>); SchemaVersion guards
/// forward migration.
/// </summary>
public sealed class PolicyLayer
{
    // v2 (TFND-185 / ADR 0009): added Assertions. Additive jsonb — a stored v1
    // layer deserializes with an empty assertion set, so nothing migrates.
    public int SchemaVersion { get; set; } = 2;

    /// <summary>Enforcement mode this layer asks for, or null to inherit. Merged
    /// as strictest-wins (Enforcing &gt; Advisory).</summary>
    public EnforcementMode? Mode { get; set; }

    /// <summary>Scanner classes this layer requires (drives the missing-scanners
    /// gate). Merged as a union — a lower layer can add, never remove.</summary>
    public List<string> RequiredScanners { get; set; } = [];

    /// <summary>Acceptance gates this layer sets. Merged as: enabled is OR;
    /// threshold is the min of the provided values (lower is stricter). Keys are
    /// well-known (<see cref="GateKeys"/>); unknown keys survive but do nothing.</summary>
    public Dictionary<string, GateConfig> Gates { get; set; } = new();

    /// <summary>Denied licence identifiers / globs. Merged as a union.</summary>
    public List<string> DeniedLicenses { get; set; } = [];

    /// <summary>POA&amp;M remediation deadlines in days, keyed by severity
    /// ("Critical", "High", "Medium", "Low"). Merged per-severity as the min
    /// (a shorter deadline is stricter).</summary>
    public Dictionary<string, int> PoamDeadlineDays { get; set; } = new();

    /// <summary>Control-disposition assertions (TFND-185 / ADR 0009): how this
    /// layer claims each OSCAL control is met — gated by a scanner, inherited, or
    /// N/A. Merged per control id as strictest-kind-wins. Controls with no
    /// assertion are Unmapped, which the no-unmapped meta-gate blocks on.</summary>
    public List<ControlAssertion> Assertions { get; set; } = [];

    public static PolicyLayer Empty() => new();
}

/// <summary>The disposition a template/layer claims for a set of controls
/// (ADR 0009). Unmapped is deliberately NOT a kind — it is the absence of any
/// assertion, which is exactly what the meta-gate exists to surface.</summary>
public enum ControlDispositionKind
{
    /// <summary>Covered by one or more automated gates (see <see cref="ControlAssertion.Gates"/>).</summary>
    Gated,
    /// <summary>Satisfied by inheritance (a hosting provider / authorizing boundary). Not our evidence to produce.</summary>
    Inherited,
    /// <summary>Does not apply, with a justification.</summary>
    NotApplicable,
}

/// <summary>One layer's claim about how a set of controls is met (ADR 0009 §2).
/// Stored inside <see cref="PolicyLayer.Assertions"/> as jsonb.</summary>
public sealed class ControlAssertion
{
    public ControlDispositionKind Kind { get; set; }

    /// <summary>OSCAL control ids this assertion covers, e.g. ["RA-5","SI-2"].</summary>
    public List<string> ControlIds { get; set; } = [];

    /// <summary>For <see cref="ControlDispositionKind.Gated"/>: the <see cref="GateKeys"/>
    /// that produce evidence for these controls. Used to derive N/A via the
    /// capability intersection (TFND-184) when the build cannot run them.</summary>
    public List<string> Gates { get; set; } = [];

    /// <summary>Why the control is inherited or N/A. Required for those kinds.</summary>
    public string? Justification { get; set; }

    /// <summary>For <see cref="ControlDispositionKind.Inherited"/>: who provides it.</summary>
    public string? InheritedFrom { get; set; }
}

/// <summary>A resolved per-control assertion after the layer merge, with the
/// layer that supplied the winning disposition.</summary>
public sealed record EffectiveAssertion(
    ControlDispositionKind Kind,
    IReadOnlyList<string> Gates,
    string? Justification,
    string? InheritedFrom,
    string Source);

/// <summary>A resolved value paired with the layer that supplied it. The source
/// is the human label of the winning layer (e.g. "FedRAMP Moderate v4",
/// "BrewingCoder", "this project").</summary>
public sealed record Sourced<T>(T Value, string Source);

/// <summary>A resolved gate: whether it blocks, its (stricter) threshold, and
/// the layer that turned it on or last tightened it.</summary>
public sealed record EffectiveGate(bool Enabled, double? Threshold, string Source);

/// <summary>
/// The strictest-across-layers result of a <see cref="PolicyLayerMerge"/>, with
/// per-value provenance so a screen can show "🔒 inherited from &lt;layer&gt;"
/// versus "↓ hardened here". Only fields at least one layer set appear.
/// </summary>
public sealed record EffectivePolicyLayer(
    Sourced<EnforcementMode>? Mode,
    IReadOnlyList<Sourced<string>> RequiredScanners,
    IReadOnlyDictionary<string, EffectiveGate> Gates,
    IReadOnlyList<Sourced<string>> DeniedLicenses,
    IReadOnlyDictionary<string, Sourced<int>> PoamDeadlineDays,
    // Per control id, the strictest-across-layers disposition claim (ADR 0009).
    IReadOnlyDictionary<string, EffectiveAssertion> Assertions);
