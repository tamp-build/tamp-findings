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
}
