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
    public int SchemaVersion { get; set; } = 1;

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

    public static PolicyLayer Empty() => new();
}

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
    IReadOnlyDictionary<string, Sourced<int>> PoamDeadlineDays);
