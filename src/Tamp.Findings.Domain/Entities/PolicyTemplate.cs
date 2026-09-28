using Tamp.Findings.Domain.Risk;

namespace Tamp.Findings.Domain.Entities;

/// <summary>
/// A versioned policy template — the top layer of the three-layer policy model
/// (ADR 0007). A template is a reusable BASELINE that clients pick and then
/// harden below; e.g. "FedRAMP Moderate v4", "Civic Baseline v2".
///
/// The template carries the hardenable overlay (<see cref="Layer"/>: mode,
/// required scanners, gates, denied licences, POA&amp;M deadlines) and links a
/// scoring <see cref="RiskPolicy"/> for the weights and bands, which stay
/// single-layer for now (ADR 0007 §2).
///
/// Loosening a template lowers the floor for every client and project under it,
/// so a save that loosens goes to InfoSec for approval (ADR 0007 §4); a save
/// that only tightens applies directly. <see cref="Version"/> is a monotonic
/// label bumped on each accepted save.
/// </summary>
public sealed class PolicyTemplate
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public required string Name { get; set; }
    public int Version { get; set; } = 1;

    /// <summary>Marks a system-seeded template (read-only origin marker, like
    /// <see cref="RiskPolicy.IsSeeded"/>). Surface it so an admin knows which
    /// shipped with the app.</summary>
    public bool IsSeeded { get; set; }

    /// <summary>The hardenable overlay this template imposes as the baseline.</summary>
    public PolicyLayer Layer { get; set; } = new();

    /// <summary>The scoring policy (weights + bands) this template uses. Null →
    /// the instance default RiskPolicy.</summary>
    public Guid? RiskPolicyId { get; set; }

    public string? CreatedByLogin { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;

    /// <summary>A short human label for provenance, e.g. "FedRAMP Moderate v4".</summary>
    public string Label => $"{Name} v{Version}";
}
