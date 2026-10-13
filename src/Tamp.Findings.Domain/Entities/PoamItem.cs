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

    // Source discriminator (ADR 0010 §9) — what produced this POA&M, so one model
    // spans the whole compliance trio. Default Finding preserves today's behaviour.
    public PoamSource SourceKind { get; set; } = PoamSource.Finding;
    // Interpreted per SourceKind: a mandate id, a ZT function ref, or an EO directive
    // ref. Free-form; null for a plain finding-derived item.
    public string? SourceRef { get; set; }
    // The in-force mandate-pack version at creation time, for point-in-time defence
    // (which mandate definition this item was raised against).
    public string? MandatePackVersion { get; set; }

    // The 800-53 controls this weakness is a weakness IN (TFND-180 increment 4).
    //
    // SourceRef above is free-form and interpreted per SourceKind — a mandate id, a ZT
    // function ref — so it cannot answer "which controls are affected", which is the
    // column the federal POA&M template puts next to the weakness and the first thing
    // an AO reads across from it. This is that column, structured: catalog control ids
    // in the catalog's own display form (CM-6, AC-4(2)), normalised and checked against
    // the current catalog on write so the stored value always resolves to a real
    // control rather than printing a typo to an AO.
    //
    // A LIST, not one id: a single weakness routinely violates several controls (an
    // unprotected boundary is both SC-7 and AC-4), and one id would force either a lie
    // or a duplicate item. Empty is allowed and ordinary — a weakness found by a
    // scanner may have no control mapped yet, and refusing to record it until someone
    // does would just push the record out of the product.
    //
    // Stored as jsonb like LinkedFindingIds: read whole with the item, never queried
    // relationally.
    public List<string> ControlIds { get; set; } = new();
}

// What raised a POA&M (ADR 0010 §9). One shared POA&M model across tamp-findings
// (supply-chain), tamp-ztt (operational mandates + ZT contradictions), and the EO
// registry that dates the mandates.
public enum PoamSource
{
    Finding = 0,
    OperationalMandate = 1,
    ZtContradiction = 2,
    SupplyChainMandate = 3,
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
