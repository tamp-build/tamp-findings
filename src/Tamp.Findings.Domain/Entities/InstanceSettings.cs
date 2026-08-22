namespace Tamp.Findings.Domain.Entities;

// Instance-wide settings. One row.
//
// Created here for the separation-of-duties switch (TFND-72); the rest of the
// System panel's settings — retention, session lifetime, outbound email,
// telemetry — land with TFND-113 and belong on this entity rather than in a
// second table.
public sealed class InstanceSettings
{
    // Fixed id: there is exactly one row, and giving it a known key means the
    // read is a point lookup and a second row cannot be created by accident.
    public static readonly Guid SingletonId = new("00000000-0000-0000-0000-000000000001");

    public Guid Id { get; set; } = SingletonId;

    // Turns the SoD advisory into a refusal. DEFAULT OFF, deliberately: a
    // three-person team genuinely needs one person to hold two conflicting
    // roles, and refusing by default would make the product unusable for
    // exactly the organisation it is aimed at. Larger programs turn it on.
    public bool EnforceSeparationOfDuties { get; set; }

    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;
}
