namespace Tamp.Findings.Domain.Entities;

// One row per CVE on the CISA Known Exploited Vulnerabilities catalog
// (https://www.cisa.gov/known-exploited-vulnerabilities-catalog).
// Synced periodically from the published JSON feed by KevFeedSyncService.
// Joined to SbomComponent.Vulnerabilities at query time on CveId so
// /aggregates can flag KEV-listed CVEs and the kevExposure gate can
// fail builds that ship with any present.
//
// CveId is the natural primary key — the catalog publishes one row per
// CVE, never two. We mirror that constraint at the DB level.
public sealed class KevAdvisory
{
    // The CVE identifier (e.g. "CVE-2021-44228"). Acts as the primary
    // key and the join key against Vulnerability.AdvisoryId.
    public required string CveId { get; set; }
    public string? VendorProject { get; set; }
    public string? Product { get; set; }
    public string? VulnerabilityName { get; set; }
    // When CISA added the CVE to the catalog. UTC date in the feed.
    public DateOnly DateAdded { get; set; }
    // CISA-assigned remediation deadline. M-22-09 / BOD 22-01 makes
    // these binding for federal agencies; for our purposes it's a
    // surface signal on the dashboard.
    public DateOnly DueDate { get; set; }
    public string? ShortDescription { get; set; }
    public string? RequiredAction { get; set; }
    // CISA-tracked: known to be used by ransomware operators ("Known"
    // or "Unknown" in the feed). We persist as a bool — "Known" → true,
    // anything else → false.
    public bool KnownRansomwareCampaignUse { get; set; }
    public string? Notes { get; set; }
    // When this row was last pulled from the feed. Lets the dashboard
    // surface "feed not refreshed in 7+ days" as a maintenance signal.
    public DateTimeOffset LastSyncedAt { get; set; } = DateTimeOffset.UtcNow;
}
