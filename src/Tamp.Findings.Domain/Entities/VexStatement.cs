namespace Tamp.Findings.Domain.Entities;

// Vulnerability Exploitability eXchange statement. Per-advisory triage
// for a package in a project — "this CVE is present but unreachable
// because <reason>." Federal auditors (CISA, FedRAMP) treat VEX as
// the official answer to "why didn't you patch this CVE?"
//
// Statements are scoped to a Project + (Purl, optional Version) +
// AdvisoryId. Keying by purl/version (not by SbomComponentId) is
// deliberate: SBOM snapshots are replace-on-ingest, but VEX outlives
// individual snapshots. The same "Log4Net 2.0.5 / CVE-2021-44228 →
// not_affected because we don't deserialize" statement remains valid
// after re-ingesting the SBOM next week.
//
// Statements are soft-retired (RetiredAt set) rather than deleted, so
// the audit trail survives "why did this CVE stop counting in May?"
// questions years later.
public sealed class VexStatement
{
    public Guid Id { get; set; } = Guid.NewGuid();

    // Project scope. Statements never cross projects today. A future
    // enhancement may add Client-scoped statements for org-wide
    // dispositions of shared deps.
    public Guid ProjectId { get; set; }

    // Package URL of the affected component (e.g.
    // "pkg:nuget/Log4Net@2.0.5"). May be version-bare
    // ("pkg:nuget/Log4Net") when the statement applies to every
    // version of the package the project ships — ComponentVersion
    // discriminates.
    public required string Purl { get; set; }
    // null = applies to every version of the package; set = only
    // matches Vulnerabilities whose SbomComponent.Version equals this.
    public string? ComponentVersion { get; set; }

    // The advisory the statement is about. Joins to
    // Vulnerability.AdvisoryId.
    public required string AdvisoryId { get; set; }

    public VexStatementStatus Status { get; set; }

    // Required by CycloneDX-VEX for `not_affected`; ignored for other
    // statuses but stored if supplied.
    public VexJustification? Justification { get; set; }

    // Free-text "why" — surfaces verbatim on the SPA next to the
    // statement. Allow Markdown; render as plain text by default to
    // sidestep injection concerns.
    public string? ImpactStatement { get; set; }

    // Optional pointer to an external write-up (issue tracker, blog
    // post, vendor advisory).
    public string? ResponseReferenceUrl { get; set; }

    public Guid AuthorUserId { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;

    // null = currently active. Setting RetiredAt is the soft-delete
    // semantic — statement no longer applied at score time, but row
    // stays for audit history.
    public DateTimeOffset? RetiredAt { get; set; }
}

// CycloneDX-VEX 1.5+ status vocabulary. Matches the wire enum so the
// bulk-ingest mapper can flow data through with minimal translation.
public enum VexStatementStatus
{
    // Triage hasn't completed yet. Counts as "still vulnerable" for
    // gating purposes — statements only relieve pressure once a final
    // determination is made.
    UnderInvestigation = 0,
    // The project IS affected; statement exists for documentation but
    // does not exclude from CVE counts.
    Affected = 1,
    // Confirmed not exploitable. Excludes the vuln from CVE counts +
    // KEV count at score time when the Justification is set.
    NotAffected = 2,
    // The project upgraded past the affected version. Excludes from
    // counts (treats the SBOM as stale relative to truth).
    Fixed = 3,
}

// Per CycloneDX-VEX 1.5 §schema for not_affected justifications.
// Required by federal auditors when claiming `not_affected`.
public enum VexJustification
{
    // No justification supplied. Statements with Status=NotAffected
    // AND Justification=None do NOT exclude from counts — federal
    // expectation is that not_affected always carries a "why."
    None = 0,
    ComponentNotPresent = 1,
    VulnerableCodeNotPresent = 2,
    VulnerableCodeNotInExecutePath = 3,
    VulnerableCodeCannotBeControlledByAdversary = 4,
    InlineMitigationsAlreadyExist = 5,
}
