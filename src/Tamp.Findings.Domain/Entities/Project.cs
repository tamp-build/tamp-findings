namespace Tamp.Findings.Domain.Entities;

public sealed class Project
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid ClientId { get; set; }
    public required string Name { get; set; }
    public string? Description { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    // Null → inherit from this project's client (which in turn falls back
    // to the system default if also null).
    public Guid? RiskPolicyId { get; set; }
    // Per-project acceptance gates (pass/fail blockers). Null → no gates
    // configured (every build passes the gate check). Distinct from
    // RiskPolicy which drives the score.
    public Risk.ProjectGatesConfig? GatesConfig { get; set; }

    public Client? Client { get; set; }
    public ICollection<Component> Components { get; set; } = [];
}
