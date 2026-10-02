using Tamp.Findings.Domain.Risk;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Domain.Entities;

/// <summary>
/// A pack-managed override of one archetype's additive obligation layer (TFND-203 phase B).
/// No row → the in-code <c>ArchetypeLayers</c> bootstrap applies. One row per archetype.
/// </summary>
public sealed class ArchetypeDefinition
{
    public ProjectArchetype Archetype { get; set; }
    public int Version { get; set; } = 1;
    public PolicyLayer Layer { get; set; } = new();
    public string? UpdatedByLogin { get; set; }
    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;
}
