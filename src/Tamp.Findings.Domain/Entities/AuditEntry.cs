using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Domain.Entities;

// Append-only record of who did what, where.
//
// This is compliance evidence, not a debug log. An assessor reads it to
// establish that risk acceptances were deliberate, that role grants were
// authorised, and that keys changed when someone says they did. That is why
// there is no update or delete path anywhere above it — an audit trail with
// an eraser is not an audit trail.
//
// The design's own note on POA&M deletion says it plainly: "a deleted item
// leaves no audit trail for the AO."
public sealed class AuditEntry
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public DateTimeOffset At { get; set; } = DateTimeOffset.UtcNow;

    // Who. UserId is null only for actions taken by the system itself —
    // scheduled workflows, ingest — and Login is stored alongside rather than
    // joined, so the record still reads correctly after a user is renamed or
    // removed.
    public Guid? UserId { get; set; }
    public required string ActorLogin { get; set; }

    // The authority they acted under. Null for system actions and for actors
    // whose authority was the instance admin flag rather than a project role.
    public ProjectRole? ActorRole { get; set; }
    public bool ActorWasAdmin { get; set; }

    // What. A stable dotted key — "poam.risk_accepted", "role.granted" — not a
    // sentence. Prose belongs in Detail; the key is what a filter and a
    // machine-readable export are built on.
    public required string Action { get; set; }
    public AuditClass Class { get; set; } = AuditClass.Other;

    // Where, as the hierarchy. All three null means instance scope.
    public Guid? ClientId { get; set; }
    public Guid? ProjectId { get; set; }
    public Guid? ComponentId { get; set; }

    // The subject of the action, when it has an id — the POA&M item, the role
    // assignment, the policy.
    public Guid? SubjectId { get; set; }
    public string? SubjectKind { get; set; }

    // Human-readable, already localised at write time to the actor's locale?
    // No — deliberately English and factual. This is a record, not UI copy,
    // and a translated audit trail cannot be compared across deployments.
    public string? Detail { get; set; }
}
