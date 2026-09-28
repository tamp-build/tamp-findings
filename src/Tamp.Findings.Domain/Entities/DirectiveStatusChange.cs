namespace Tamp.Findings.Domain.Entities;

// The effective-dated status history of a directive (ADR 0011 §4) — the point-in-time
// engine. NEVER deleted or mutated: every status transition is an append-only row with
// the date it took effect and the instrument that caused it. A directive's status as
// of any date is the latest change on or before that date. A rescind is forward-dated,
// not retroactive: a system non-compliant with a since-rescinded directive stays
// historically non-compliant as-of-then and simply stops accruing findings after the
// rescind date. Append-only is enforced in FindingsDbContext (the GuardAuditTrail path).
public sealed class DirectiveStatusChange
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public Guid DirectiveId { get; set; }
    public DirectiveStatus Status { get; set; }

    // When this status took effect (e.g. the amending instrument's issue date for a
    // rescind), distinct from RecordedAt (when the row was written).
    public DateTimeOffset EffectiveDate { get; set; }

    // The instrument whose amendment/revocation caused this change, if any.
    public Guid? CausedByInstrumentId { get; set; }

    public DateTimeOffset RecordedAt { get; set; } = DateTimeOffset.UtcNow;
}

public enum DirectiveStatus { Active = 0, Rescinded = 1, Superseded = 2 }
