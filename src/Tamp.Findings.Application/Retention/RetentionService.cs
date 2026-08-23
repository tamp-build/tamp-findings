using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Tamp.Findings.Application.Auditing;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Application.Retention;

/// <summary>
/// Enforcing the retention window (TFND-13 / F12.4).
///
/// The settings existed and nothing read them, which is worse than not having
/// them: an operator who set "keep findings 90 days" to satisfy a data-handling
/// policy had a screen telling them it was done and a database that kept
/// everything forever.
///
/// This deletes evidence, permanently, from a product whose entire job is being
/// able to show what was true. So it is built to refuse rather than to reach:
///
///  * Default is KEEP FOREVER. Null retention deletes nothing, and that is the
///    honest default — an attestation signed three years ago cites findings
///    from three years ago.
///  * It never deletes a build an ATTESTATION covers. The snapshot stores its
///    own document, so the signature stays verifiable either way, but an
///    assessor following it back to the build it names should find the build.
///  * It never deletes a finding a POA&amp;M item links. That is an open
///    commitment to fix something; deleting the thing it points at would leave
///    a plan of action whose subject cannot be inspected.
///  * It never deletes a finding with a live suppression or an Accepted status.
///    Both are decisions somebody made about that specific finding, and the
///    decision outliving its subject is how a suppression becomes unexplainable.
///
/// Everything skipped is COUNTED and logged. A retention sweep that quietly
/// keeps more than it was told to is defensible; one that does so silently is
/// how an operator finds out during an audit.
/// </summary>
public sealed class RetentionService
{
    private readonly FindingsDbContext _db;
    private readonly AuditLog _audit;
    private readonly ILogger<RetentionService> _log;

    public RetentionService(FindingsDbContext db, AuditLog audit, ILogger<RetentionService> log)
    {
        _db = db;
        _audit = audit;
        _log = log;
    }

    public async Task<RetentionOutcome> SweepAsync(DateTimeOffset asOf, CancellationToken ct = default)
    {
        var settings = await _db.InstanceSettings.AsNoTracking()
            .SingleOrDefaultAsync(s => s.Id == InstanceSettings.SingletonId, ct);

        var findingDays = settings?.FindingRetentionDays;
        var buildDays = settings?.BuildRetentionDays;

        // Nothing configured, nothing to do. Not an error and not worth a log
        // line every day — keeping everything is the default and the common
        // case.
        if (findingDays is null && buildDays is null) return RetentionOutcome.Disabled;

        var findings = findingDays is { } fd ? await SweepFindingsAsync(asOf.AddDays(-fd), asOf, ct) : (0, 0);
        var builds = buildDays is { } bd ? await SweepBuildsAsync(asOf.AddDays(-bd), ct) : (0, 0);

        var outcome = new RetentionOutcome(
            true, findings.Item1, findings.Item2, builds.Item1, builds.Item2);

        if (outcome.FindingsDeleted == 0 && outcome.BuildsDeleted == 0) return outcome;

        // Audited as Other: retention is housekeeping an operator configured,
        // not a risk decision anyone took today. It is in the trail because
        // "where did the March findings go" is a question with exactly one
        // correct answer and it should be findable.
        _audit.RecordSystem(
            "retention.swept",
            AuditClass.Other,
            ScopeTarget.Instance,
            detail: $"Deleted {outcome.FindingsDeleted} finding(s) and {outcome.BuildsDeleted} build(s); "
                  + $"kept {outcome.FindingsKept} finding(s) and {outcome.BuildsKept} build(s) that "
                  + "evidence still refers to.");

        await _db.SaveChangesAsync(ct);

        _log.LogInformation(
            "Retention swept: deleted {Findings} finding(s) and {Builds} build(s); "
            + "kept {KeptFindings} finding(s) and {KeptBuilds} build(s) still referenced by evidence.",
            outcome.FindingsDeleted, outcome.BuildsDeleted, outcome.FindingsKept, outcome.BuildsKept);

        return outcome;
    }

    private async Task<(int Deleted, int Kept)> SweepFindingsAsync(
        DateTimeOffset cutoff, DateTimeOffset asOf, CancellationToken ct)
    {
        // LastSeen, not FirstSeen. A finding first raised two years ago and
        // still present on last night's build is a current problem, and
        // deleting it because it is old would remove the oldest and therefore
        // most overdue items — exactly backwards.
        var candidates = await _db.Findings
            .Where(f => f.LastSeen < cutoff)
            .ToArrayAsync(ct);

        if (candidates.Length == 0) return (0, 0);

        var ids = candidates.Select(f => f.Id).ToArray();

        // POA&M links are a List<Guid> column, so this cannot be a join. The
        // set is small — an instance has tens of POA&M items, not millions.
        var linked = (await _db.PoamItems.AsNoTracking()
                .Select(p => p.LinkedFindingIds)
                .ToArrayAsync(ct))
            .SelectMany(list => list)
            .ToHashSet();

        var suppressed = await _db.Suppressions.AsNoTracking()
            .Where(s => s.FindingId != null && ids.Contains(s.FindingId!.Value))
            .Select(s => s.FindingId!.Value)
            .ToArrayAsync(ct);
        var explained = suppressed.ToHashSet();

        var deleted = 0;
        var kept = 0;

        foreach (var finding in candidates)
        {
            // Accepted is a signed risk decision about this exact finding.
            if (finding.Status == FindingStatus.Accepted
                || linked.Contains(finding.Id)
                || explained.Contains(finding.Id))
            {
                kept++;
                continue;
            }

            _db.Findings.Remove(finding);
            deleted++;
        }

        return (deleted, kept);
    }

    private async Task<(int Deleted, int Kept)> SweepBuildsAsync(DateTimeOffset cutoff, CancellationToken ct)
    {
        var candidates = await _db.ComponentVersions
            .Where(v => v.CreatedAt < cutoff)
            .ToArrayAsync(ct);

        if (candidates.Length == 0) return (0, 0);

        // Attested commits, by sha within their project. A snapshot stores its
        // own document so the signature survives either way — but an assessor
        // following an attestation back to the build it names should find the
        // build, not a gap.
        var attested = await _db.AttestationSnapshots.AsNoTracking()
            .Select(a => new { a.ProjectId, a.CommitSha })
            .ToArrayAsync(ct);

        var attestedKeys = attested
            .Select(a => $"{a.ProjectId}|{a.CommitSha}")
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var projectOf = await _db.Components.AsNoTracking()
            .Select(c => new { c.Id, c.ProjectId })
            .ToDictionaryAsync(c => c.Id, c => c.ProjectId, ct);

        var deleted = 0;
        var kept = 0;

        foreach (var version in candidates)
        {
            var isAttested = version.CommitSha is { Length: > 0 } sha
                && projectOf.TryGetValue(version.ComponentId, out var projectId)
                && attestedKeys.Contains($"{projectId}|{sha}");

            if (isAttested)
            {
                kept++;
                continue;
            }

            _db.ComponentVersions.Remove(version);
            deleted++;
        }

        return (deleted, kept);
    }
}

/// <summary>
/// What a sweep did, including what it REFUSED to do.
///
/// The kept counts are the point. A sweep that keeps more than it was told to
/// is defensible; one that does so silently is how an operator discovers it
/// mid-audit.
/// </summary>
public sealed record RetentionOutcome(
    bool Enabled, int FindingsDeleted, int FindingsKept, int BuildsDeleted, int BuildsKept)
{
    public static RetentionOutcome Disabled { get; } = new(false, 0, 0, 0, 0);
}
