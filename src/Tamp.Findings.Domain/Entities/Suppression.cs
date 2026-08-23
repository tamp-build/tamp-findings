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

    // The tenant this suppression belongs to (TFND-132).
    //
    // SingleFinding and RuleOnComponent are anchored by their subject, so these
    // are derived rather than load-bearing. For RuleOnFile and RuleEverywhere
    // they are the ONLY thing bounding the row: without them the matcher
    // silenced a rule for every client on the instance, and there was no record
    // of which client had asked for it.
    //
    // Nullable because rows predating the migration have no answer. A null
    // ClientId means "instance-wide, provenance unknown" — the matcher treats
    // it as the legacy global row it is, and the UI says so, rather than
    // inventing an attribution that would be a guess presented as a fact.
    public Guid? ClientId { get; set; }
    public Guid? ProjectId { get; set; }

    public required Guid CreatedByUserId { get; set; }
    public ProjectRole CreatedByRole { get; set; }
    public required string Reason { get; set; }
    public DateTimeOffset? ExpiresAt { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}
