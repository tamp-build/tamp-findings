using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Tamp.Findings.Application.Risk;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Application.Ingest;

/// <summary>
/// One source of truth per component-CVE (TFND-16).
///
/// The defect this fixes: there were two parallel CVE paths and only one of
/// them reached the SBOM picture.
///
///   Grype       → /ingest/sbom      → Vulnerability rows → counted
///   OsvScanner  → /ingest/findings  → Finding rows       → orphaned
///   Trivy (cve) → /ingest/findings  → Finding rows       → orphaned
///
/// So the same CVE on the same package counted once, twice or not at all,
/// depending on which scanner happened to see it — and a project running only
/// OsvScanner had CVEs the score never saw, which is the worst version: a clean
/// number that nobody measured.
///
/// The ticket offered two fixes and preferred (a), "post-process into
/// Vulnerability rows alongside Grype", because it gives one source of truth
/// per component-CVE rather than a count that has to remember which table each
/// half lives in. This is (a).
///
/// It runs after BOTH ingest paths, because the order is not guaranteed: a
/// findings ingest may arrive before the SBOM that gives it something to attach
/// to, or after.
/// </summary>
public sealed class CveReconciler
{
    private readonly FindingsDbContext _db;
    private readonly ILogger<CveReconciler> _log;

    public CveReconciler(FindingsDbContext db, ILogger<CveReconciler> log)
    {
        _db = db;
        _log = log;
    }

    /// <summary>
    /// Rule ids that name an advisory.
    ///
    /// CVE and GHSA are the two a dependency scanner emits; OSV's own ids
    /// (GO-2024-1234, PYSEC-2024-1, RUSTSEC-2024-0001) follow the same shape of
    /// "ecosystem prefix, year, sequence" and are matched by the third branch.
    ///
    /// Deliberately NOT "anything with a dash and a number". A SAST rule called
    /// S2094-3 must never be mistaken for an advisory and written into the CVE
    /// table, where it would inflate a count somebody ships against.
    /// </summary>
    private static readonly Regex AdvisoryId = new(
        @"^(CVE-\d{4}-\d{4,}|GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}|(GO|PYSEC|RUSTSEC|OSV|GMS)-\d{4}-\d+)$",
        RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.CultureInvariant,
        TimeSpan.FromMilliseconds(100));

    public static bool LooksLikeAdvisory(string ruleId) =>
        !string.IsNullOrWhiteSpace(ruleId) && AdvisoryId.IsMatch(ruleId.Trim());

    /// <summary>
    /// Attach every reconcilable CVE finding on this build to its SBOM
    /// component.
    /// </summary>
    public async Task<ReconcileResult> ReconcileAsync(
        IReadOnlyCollection<Guid> componentVersionIds, CancellationToken ct = default)
    {
        if (componentVersionIds.Count == 0) return ReconcileResult.Empty;

        // Findings that CLAIM to be about an advisory. The rule-id shape is
        // checked in memory rather than in SQL: the pattern is the load-bearing
        // guard against writing a SAST rule into the CVE table, and it belongs
        // somewhere it can be read and tested, not in a LIKE.
        var candidates = await _db.Findings
            .Where(f => componentVersionIds.Contains(f.ComponentVersionId)
                     && f.Status == FindingStatus.Open
                     && (f.Scanner == ScannerKind.OsvScanner
                      || (f.Scanner == ScannerKind.Trivy && f.SubCategory == "vulnerability")))
            .ToArrayAsync(ct);

        var advisories = candidates.Where(f => LooksLikeAdvisory(f.RuleId)).ToArray();
        if (advisories.Length == 0) return ReconcileResult.Empty;

        // Components on the same builds, so an advisory can only ever attach to
        // a package this build actually ships.
        var components = await _db.SbomComponents
            .Where(c => componentVersionIds.Contains(c.SbomSnapshot!.ComponentVersionId))
            .Select(c => new { c.Id, c.Purl, c.SbomSnapshot!.ComponentVersionId })
            .ToArrayAsync(ct);

        var byBarePurl = components
            .GroupBy(c => VexResolver.StripPurlVersion(c.Purl), StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.ToArray(), StringComparer.OrdinalIgnoreCase);

        var existing = (await _db.Vulnerabilities
                .Where(v => componentVersionIds.Contains(v.SbomComponent!.SbomSnapshot!.ComponentVersionId))
                .Select(v => new { v.SbomComponentId, v.AdvisoryId })
                .ToArrayAsync(ct))
            .Select(v => (v.SbomComponentId, v.AdvisoryId))
            .ToHashSet();

        var attached = 0;
        var alreadyKnown = 0;
        var unattached = new List<string>();

        foreach (var finding in advisories)
        {
            if (string.IsNullOrWhiteSpace(finding.Purl))
            {
                // The scanner said there is a CVE but not which package. There
                // is nothing to attach it to, and inventing a match from a file
                // path would put a vulnerability on a component that may not
                // have it — which is worse than the gap, because the gap is
                // visible and the wrong answer is not.
                //
                // TODO(TAM-281): the tamp OsvScanner and Trivy wrappers do not
                // emit purl on findings yet. Until they do, advisories from
                // those scanners land here and stay out of the CVE count. The
                // ingest response returns the count so a pipeline can fail on
                // it rather than discovering it in a score.
                unattached.Add(finding.RuleId);
                continue;
            }

            var bare = VexResolver.StripPurlVersion(finding.Purl.Trim());

            if (!byBarePurl.TryGetValue(bare, out var matches))
            {
                // A CVE against a package this build's SBOM does not list. The
                // usual cause is an SBOM that has not been ingested yet, and
                // the reconciler runs again when it is.
                unattached.Add(finding.RuleId);
                continue;
            }

            foreach (var component in matches.Where(c => c.ComponentVersionId == finding.ComponentVersionId))
            {
                if (!existing.Add((component.Id, finding.RuleId)))
                {
                    // Grype already reported it. That is the DEDUPLICATION this
                    // whole class exists for: one advisory on one component is
                    // one row, whichever scanner found it first.
                    alreadyKnown++;
                    continue;
                }

                _db.Vulnerabilities.Add(new Vulnerability
                {
                    SbomComponentId = component.Id,
                    AdvisoryId = finding.RuleId,
                    Severity = finding.Severity,
                    Title = finding.Title,
                    Description = finding.Description,
                    // The scanner that actually found it, not the one that
                    // usually populates this table. "Where did this come from"
                    // is a question people ask when a CVE appears.
                    Source = finding.Scanner,
                });

                attached++;
            }
        }

        if (attached > 0) await _db.SaveChangesAsync(ct);

        if (unattached.Count > 0)
        {
            // Logged rather than swallowed: a CVE that could not be attached is
            // NOT in the score, and a silent gap in a security score is the
            // exact failure this product exists to prevent.
            _log.LogWarning(
                "{Count} advisory finding(s) could not be attached to an SBOM component and are "
                + "therefore not in the CVE count: {Advisories}. Either no SBOM has been ingested "
                + "for this build yet, or the scanner did not report which package it found them in.",
                unattached.Count, string.Join(", ", unattached.Distinct().Take(10)));
        }

        return new ReconcileResult(attached, alreadyKnown, unattached.Count);
    }
}

/// <summary>
/// What a reconciliation pass did.
///
/// <see cref="Unattached"/> is the number worth surfacing: those CVEs exist as
/// findings and are NOT in the CVE count, which is a gap somebody should be able
/// to see rather than infer.
/// </summary>
public sealed record ReconcileResult(int Attached, int AlreadyKnown, int Unattached)
{
    public static readonly ReconcileResult Empty = new(0, 0, 0);
}
