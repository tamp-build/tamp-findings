using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Domain.Entities;

// Plan of Action & Milestones (POA&M) entry. Federal terminology
// per NIST SP 800-53 CA-5 / FedRAMP Continuous Monitoring — the
// formal record that a known weakness exists, who owns it, and
// when it will close. Auditors expect a POA&M for any vulnerability
// that isn't fixed-on-detection AND isn't explained away by a VEX
// statement. AOs (Authorizing Officials) review POA&M monthly.
//
// Scope: per-project. A POA&M can optionally link to specific
// Finding/Vulnerability ids that motivated it (LinkedFindingIds) but
// can also stand alone — e.g. an architectural weakness discovered
// during an annual assessment that no scanner caught.
//
// Lifecycle: Open → InProgress → Completed (or RiskAccepted /
// Cancelled). Reaching a terminal state stamps ClosedAt; the row
// stays for the audit trail.
public sealed class PoamItem
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public Guid ProjectId { get; set; }

    // One-line summary; appears in lists. "Upgrade Log4Net past
    // 2.0.5", "Remediate XSS in /admin search", etc.
    public required string Title { get; set; }

    // Free-text — the weakness as it would be described to an AO.
    // Markdown allowed; SPA renders plain text by default.
    public required string WeaknessDescription { get; set; }

    // How the project intends to close the weakness. Required by
    // the federal POA&M template; nullable here because draft
    // entries may have the plan TBD.
    public string? MitigationPlan { get; set; }

    // What it will cost in people / budget / dependencies. Federal
    // POA&M template field; surfaces in CSV exports for AO review.
    public string? ResourcesRequired { get; set; }

    // Severity in the same scale as Finding.Severity. Drives
    // sort order and (optionally) downstream prioritisation.
    public Severity Severity { get; set; }

    public PoamStatus Status { get; set; } = PoamStatus.Open;

    // Due date the team committed to with the AO. Null means
    // unscheduled (a "we'll get to it" placeholder); past-due
    // gate skips unscheduled items rather than failing on them.
    public DateTimeOffset? ScheduledCompletionDate { get; set; }
    // When the item actually closed (any terminal state stamps this).
    public DateTimeOffset? ActualCompletionDate { get; set; }

    // Optional links to specific Findings or Vulnerabilities the
    // item was opened against. Stored as a jsonb Guid array so the
    // SPA can deep-link back to the originating row. LinkedFindings
    // do NOT auto-close when the POA&M closes — the user owns the
    // transition. Likewise, closing a finding does not auto-close
    // its POA&M (closing the finding may not address the underlying
    // weakness; the AO still wants explicit acknowledgement).
    public List<Guid> LinkedFindingIds { get; set; } = new();

    // External reference (ticket URL, AO memo, vendor advisory).
    public string? ReferenceUrl { get; set; }

    public Guid AuthorUserId { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;
    // Set when Status becomes Completed, RiskAccepted, or Cancelled.
    // null means the item is still live and counts toward gates.
    public DateTimeOffset? ClosedAt { get; set; }
}

public enum PoamStatus
{
    // Newly opened; mitigation hasn't started.
    Open = 0,
    // Team is actively working the mitigation.
    InProgress = 1,
    // Mitigation completed; weakness no longer present.
    Completed = 2,
    // AO accepted the residual risk; weakness remains but is
    // documented as an accepted living risk. Does NOT count
    // against past-due gates (acceptance is the terminal state).
    RiskAccepted = 3,
    // Item was opened in error or the weakness was determined not
    // to exist after triage.
    Cancelled = 4,
}
