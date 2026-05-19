using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Domain.Entities;

public sealed class Suppression
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public SuppressionScope Scope { get; set; }

    // Populated depending on Scope. Domain invariants enforced by the
    // service layer when the entity is created — not in the entity itself.
    public Guid? FindingId { get; set; }
    public string? RuleId { get; set; }
    public Guid? ComponentId { get; set; }
    public string? FilePath { get; set; }

    public required Guid CreatedByUserId { get; set; }
    public ProjectRole CreatedByRole { get; set; }
    public required string Reason { get; set; }
    public DateTimeOffset? ExpiresAt { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}
