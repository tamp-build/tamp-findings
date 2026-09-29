using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Application.Compliance;

/// <summary>
/// Ingests reverse-examination advisories (ADR 0013) into <see cref="DecisionDiagnostic"/> rows.
/// tamp.findings is the sink: it never re-evaluates anything. Each advisory binds to a build by
/// its <c>provenance.commitSha</c>, resolved to a ComponentVersion under the token's project(s),
/// exactly like conformance evidence. Upserts by (build, ruleId, location): a re-run refreshes the
/// prior advisory rather than duplicating it.
///
/// These are ADVISORY only — they never gate, never carry a verdict, never raise a POA&amp;M.
/// </summary>
public sealed class DecisionDiagnosticIngestService(FindingsDbContext db)
{
    public const string RulePrefix = "undocumented-decision:";

    public async Task<DiagnosticIngestResult> IngestAsync(
        IReadOnlyList<Guid> candidateProjectIds,
        IReadOnlyList<DiagnosticEventDto> events,
        CancellationToken ct = default)
    {
        // Keep only the undocumented-decision notes that carry enough to attach.
        var notes = events
            .Where(e => string.Equals(e.Type, BuildEventTypes.DiagnosticEmitted, StringComparison.Ordinal)
                     || string.Equals(e.Payload?.Type, BuildEventTypes.DiagnosticEmitted, StringComparison.Ordinal))
            .Select(e => e.Payload)
            .Where(p => p is not null
                     && p.RuleId is { Length: > 0 } rid
                     && rid.StartsWith(RulePrefix, StringComparison.Ordinal)
                     && !string.IsNullOrWhiteSpace(p.Message))
            .Select(p => p!)
            .ToList();

        var skipped = events.Count - notes.Count;

        var shas = notes
            .Select(p => p.Provenance?.CommitSha)
            .Where(s => !string.IsNullOrWhiteSpace(s))
            .Select(s => s!)
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        var cvByCommit = new Dictionary<string, Guid>(StringComparer.Ordinal);
        if (shas.Length > 0)
        {
            var rows = await db.ComponentVersions.AsNoTracking()
                .Where(cv => cv.CommitSha != null && shas.Contains(cv.CommitSha)
                    && db.Components.Any(c => c.Id == cv.ComponentId && candidateProjectIds.Contains(c.ProjectId)))
                .OrderBy(cv => cv.CreatedAt)
                .Select(cv => new { cv.CommitSha, cv.Id })
                .ToListAsync(ct);
            foreach (var r in rows)
                cvByCommit.TryAdd(r.CommitSha!, r.Id);   // first (oldest) CV per commit
        }

        var accepted = 0;
        var builds = new HashSet<string>(StringComparer.Ordinal);
        var now = DateTimeOffset.UtcNow;

        foreach (var p in notes)
        {
            var sha = p.Provenance?.CommitSha;
            if (sha is null || !cvByCommit.TryGetValue(sha, out var cvId))
            {
                skipped++;   // no build to bind to (missing/unknown commit, or out of scope)
                continue;
            }

            var ruleId = p.RuleId!;
            var kind = ruleId[RulePrefix.Length..];
            var location = FormatLocation(p.Location);
            var controls = p.ControlRefs is { Count: > 0 } ? p.ControlRefs : ["CM-3"];

            var existing = await db.DecisionDiagnostics.FirstOrDefaultAsync(
                d => d.ComponentVersionId == cvId && d.RuleId == ruleId && d.Location == location, ct);

            if (existing is null)
            {
                db.DecisionDiagnostics.Add(new DecisionDiagnostic
                {
                    ComponentVersionId = cvId,
                    RuleId = ruleId,
                    Kind = kind.Length > 0 ? kind : "decision",
                    Summary = p.Message!,
                    Location = location,
                    CommitSha = sha,
                    ControlRefs = controls,
                    DetectedAt = now,
                });
            }
            else
            {
                existing.Kind = kind.Length > 0 ? kind : "decision";
                existing.Summary = p.Message!;
                existing.CommitSha = sha;
                existing.ControlRefs = controls;
                existing.DetectedAt = now;
            }

            accepted++;
            builds.Add(sha);
        }

        if (accepted > 0) await db.SaveChangesAsync(ct);
        return new DiagnosticIngestResult(accepted, skipped, builds.ToArray());
    }

    private static string? FormatLocation(DiagnosticLocationDto? loc) =>
        loc?.File is not { Length: > 0 } file ? null : loc.Line is { } line ? $"{file}:{line}" : file;
}
