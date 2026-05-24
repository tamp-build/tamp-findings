namespace Tamp.Findings.Domain.Entities;

public sealed class Client
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public required string Name { get; set; }
    public string? Description { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    // Null → fall back to the system default policy. Set → applies to
    // every project under this client unless the project overrides.
    public Guid? RiskPolicyId { get; set; }

    public ICollection<Project> Projects { get; set; } = [];
}
