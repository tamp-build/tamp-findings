using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Tamp.Findings.Application.Auditing;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Suppressions;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Application.Suppressions;

/// <summary>
/// Reopening findings whose suppression has lapsed (TFND-11 / F10.5).
///
/// The ingest path already re-evaluates suppression coverage on every finding
/// it touches, so a lapsed suppression reopens its finding — the next time that
/// exact scanner posts to that exact component version.
///
/// Which is the gap. Nothing else in this product reads a Suppressed finding:
/// every query, every count, the score and every gate filter on Open. So a
/// suppression that expired in March stays in force until somebody happens to
/// build, and on a component that ships quarterly that is months of a finding
/// being invisible AFTER the decision to ignore it ran out.
///
/// An expiry that only takes effect when someone builds is not an expiry. This
/// sweeps on a timer instead, so the date on the suppression is the date it
/// stops working.
/// </summary>
public sealed class SuppressionExpiryService
{
    private readonly FindingsDbContext _db;
    private readonly AuditLog _audit;
    private readonly ILogger<SuppressionExpiryService> _log;

    public SuppressionExpiryService(
        FindingsDbContext db, AuditLog audit, ILogger<SuppressionExpiryService> log)
    {
        _db = db;
        _audit = audit;
        _log = log;
    }

    /// <summary>
    /// Reopen every finding no longer covered by an active suppression.
    /// </summary>
    public async Task<int> SweepAsync(DateTimeOffset asOf, CancellationToken ct = default)
    {
        // Where each suppressed finding sits in the tree.
        //
        // Read separately and NO-TRACKING, then the findings themselves are
        // loaded tracked below. That split is deliberate: EF applies tracking
        // behaviour per QUERY, not per source, so one AsNoTracking() among the
        // joins makes the whole result detached — and then `finding.Status =
        // Open` writes to an object SaveChanges has never heard of. It fails
        // silently, which is the worst way for a sweep like this to fail: the
        // audit entry still lands, so the log says the finding reopened and the
        // finding did not.
        var located = await (
            from f in _db.Findings.AsNoTracking()
            join cv in _db.ComponentVersions.AsNoTracking() on f.ComponentVersionId equals cv.Id
            join c in _db.Components.AsNoTracking() on cv.ComponentId equals c.Id
            join p in _db.Projects.AsNoTracking() on c.ProjectId equals p.Id
            where f.Status == FindingStatus.Suppressed
            select new { f.Id, p.ClientId, ProjectId = p.Id, ComponentId = c.Id })
            .ToArrayAsync(ct);

        if (located.Length == 0) return 0;

        var targets = located.ToDictionary(
            r => r.Id, r => new SuppressionTarget(r.ClientId, r.ProjectId, r.ComponentId));

        var ids = targets.Keys.ToArray();

        // Only Suppressed. Accepted is an explicit "we know, and we are
        // accepting the risk" decision with its own lifecycle, and a sweep that
        // quietly reopened those would be overruling a person who signed
        // something.
        var suppressed = await _db.Findings
            .Where(f => ids.Contains(f.Id) && f.Status == FindingStatus.Suppressed)
            .ToArrayAsync(ct);

        // The whole pool, expired ones included. Loading only the active ones
        // would be enough to answer "is it still covered", but not enough to
        // say WHICH suppression lapsed — and an audit entry that cannot name
        // the expired decision is not much of a trail.
        var pool = await _db.Suppressions.AsNoTracking().ToArrayAsync(ct);

        var reopened = 0;

        foreach (var finding in suppressed)
        {
            var target = targets[finding.Id];

            var stillCovered = SuppressionMatcher.AnyCovers(
                pool, target, finding.RuleId, finding.FilePath, finding.Id, asOf);

            // A finding can be covered by more than one suppression. One
            // lapsing while another still stands is not a reopen — checking
            // "did any suppression expire" instead of "is it still covered"
            // would reopen findings somebody deliberately re-suppressed.
            if (stillCovered) continue;

            finding.Status = FindingStatus.Open;
            reopened++;

            // Risk class. This changes the score, and it can flip a gate from
            // pass to fail without anybody touching the project — which is
            // precisely the event an assessor would want to find in the log.
            _audit.RecordSystem(
                "finding.suppression_expired",
                AuditClass.Risk,
                new ScopeTarget(target.ClientId, target.ProjectId, target.ComponentId),
                subjectId: finding.Id,
                subjectKind: nameof(Finding),
                detail: $"{finding.RuleId} reopened — {Describe(pool, target, finding, asOf)}");
        }

        if (reopened == 0) return 0;

        await _db.SaveChangesAsync(ct);

        // Information, not debug. Findings reappearing without anyone acting is
        // surprising if you do not know why, and this is the line that explains
        // the score moving overnight.
        _log.LogInformation(
            "Reopened {Count} finding(s) whose suppression expired on or before {AsOf:u}.",
            reopened, asOf);

        return reopened;
    }

    /// <summary>
    /// Which lapsed suppression was covering this, for the audit detail.
    ///
    /// Best effort: it names the most recently expired suppression that WOULD
    /// have covered the finding had it still been live. Saying "a suppression
    /// expired" without saying which one leaves the reader to go looking, and
    /// the point of the entry is that they should not have to.
    /// </summary>
    private static string Describe(
        IReadOnlyList<Suppression> pool, SuppressionTarget target, Finding finding, DateTimeOffset asOf)
    {
        var lapsed = pool
            .Where(s => s.ExpiresAt is { } expiry && expiry <= asOf)
            // Re-test against a moment before the expiry, so the matcher's own
            // active check does not immediately reject it.
            .Where(s => SuppressionMatcher.Covers(
                s, target, finding.RuleId, finding.FilePath, finding.Id,
                s.ExpiresAt!.Value.AddSeconds(-1)))
            .OrderByDescending(s => s.ExpiresAt)
            .FirstOrDefault();

        return lapsed is null
            ? "no active suppression covers it any longer"
            : $"the {lapsed.Scope} suppression that expired {lapsed.ExpiresAt:yyyy-MM-dd} "
              + $"(\"{Trim(lapsed.Reason)}\") no longer applies";
    }

    private static string Trim(string reason) =>
        reason.Length <= 120 ? reason : reason[..117] + "…";
}
