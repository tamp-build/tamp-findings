using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Application.Risk;

// Builds the set of Vulnerability ids that an active VEX statement has
// taken out of the CVE picture for a project. Used by /aggregates and
// RiskInputsBuilder to subtract VEX-suppressed CVEs from the count
// inputs that feed the scorer + the kevExposure gate.
//
// "Active" = not retired, and the status falls in the "treat as
// resolved" bucket: NotAffected with a justification, or Fixed.
// NotAffected with Justification=None still counts as vulnerable —
// federal expectation is that not_affected always carries a "why."
public sealed class VexResolver(FindingsDbContext db)
{
    public async Task<HashSet<Guid>> SuppressedVulnIdsForProjectAsync(Guid projectId, CancellationToken ct)
    {
        // Pull all active project-scoped statements. Typical projects
        // will have a few dozen at most; in-memory join against the
        // project's vulnerabilities is cheaper than a four-way SQL
        // join through SbomSnapshot → ComponentVersion → Project.
        // The "suppressing" predicate is inlined here (rather than via
        // IsSuppressingStatus) because EF can't translate method calls
        // on a service object into SQL.
        var statements = await db.VexStatements.AsNoTracking()
            .Where(v => v.ProjectId == projectId
                     && v.RetiredAt == null
                     && (v.Status == VexStatementStatus.Fixed
                      || (v.Status == VexStatementStatus.NotAffected
                          && v.Justification != null
                          && v.Justification != VexJustification.None)))
            .Select(v => new { v.AdvisoryId, v.Purl, v.ComponentVersion })
            .ToListAsync(ct);
        if (statements.Count == 0) return [];

        // Match (Vulnerability.AdvisoryId, SbomComponent.Purl,
        // SbomComponent.Version) against statements scoped to this
        // project's SBOM snapshots. Project scope on the vuln side
        // is via the SbomComponent → SbomSnapshot → ComponentVersion
        // → Component → Project chain.
        var advisoryIds = statements.Select(s => s.AdvisoryId).Distinct().ToList();
        // Prefilter is AdvisoryId only — purl-form mismatch (bare vs
        // full) makes a SQL-side purl filter unreliable. AdvisoryId is
        // the tight predicate anyway; the in-memory match below
        // handles the purl/version comparison.
        var candidates = await db.Vulnerabilities.AsNoTracking()
            .Where(v => v.SbomComponent!.SbomSnapshot!.ComponentVersion!.Component!.ProjectId == projectId)
            .Where(v => advisoryIds.Contains(v.AdvisoryId))
            .Select(v => new
            {
                v.Id, v.AdvisoryId,
                v.SbomComponent!.Purl,
                v.SbomComponent.Version,
            })
            .ToListAsync(ct);

        var suppressed = new HashSet<Guid>();
        foreach (var cand in candidates)
        {
            // SbomComponent.Purl is stored as the full purl
            // (pkg:nuget/Foo@1.2.3) while VexStatement.Purl is the
            // bare form (pkg:nuget/Foo) with version in its own
            // column. Normalise both to the bare purl for the
            // comparison, then check the version separately.
            var candBarePurl = StripPurlVersion(cand.Purl);
            var hit = statements.Any(s =>
                s.AdvisoryId == cand.AdvisoryId
                && StripPurlVersion(s.Purl) == candBarePurl
                && (s.ComponentVersion is null || s.ComponentVersion == cand.Version));
            if (hit) suppressed.Add(cand.Id);
        }
        return suppressed;
    }

    // pkg:nuget/Foo@1.2.3 → pkg:nuget/Foo. Returns the input unchanged
    // when no '@' separates name from version.
    private static string StripPurlVersion(string purl)
    {
        var at = purl.LastIndexOf('@');
        return at < 4 ? purl : purl[..at];
    }

    // Statements that take a vulnerability OUT of the gating picture.
    // - NotAffected with a real justification: confirmed unexploitable.
    // - Fixed: upgrade already shipped (SBOM may lag).
    // Other states keep the vulnerability in the count.
    public static bool IsSuppressingStatus(VexStatementStatus status, VexJustification? justification) =>
        status switch
        {
            VexStatementStatus.NotAffected => justification is not null
                                              && justification != VexJustification.None,
            VexStatementStatus.Fixed => true,
            _ => false,
        };
}
