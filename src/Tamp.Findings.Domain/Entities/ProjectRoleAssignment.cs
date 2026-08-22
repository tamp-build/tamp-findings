using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Domain.Entities;

// Assignment of one of the three named roles (InfoSecOfficer / LeadDev /
// Architect) to a user, scoped to a Client, Project, or Component. Lower
// tiers override higher tiers — see TFND-3 / F2.
public sealed class ProjectRoleAssignment
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid UserId { get; set; }
    public ProjectRole Role { get; set; }

    public Guid? ClientId { get; set; }
    public Guid? ProjectId { get; set; }
    public Guid? ComponentId { get; set; }

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    // Who granted this, so the trail does not depend on matching timestamps
    // against the audit log.
    public Guid? GrantedByUserId { get; set; }

    // Separation-of-duties conflict introduced BY THIS GRANT, recorded at
    // grant time (TFND-72).
    //
    // Stored rather than recomputed on read, and that is the point: the
    // hand-off wants "an assessor [to] see it was a deliberate choice rather
    // than an oversight". Recomputing would show today's conflicts against
    // today's rules; this shows what the granter was told and accepted at the
    // moment they accepted it.
    //
    // Null means no conflict was introduced. Non-null is the advisory text.
    public string? SodConflict { get; set; }
}
