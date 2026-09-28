using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Compliance;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Application.Compliance;

/// <summary>
/// Ingests ADR-conformance verdicts (core ADR 0023) into <see cref="ConformanceFinding"/>
/// rows. tamp.findings is the sink: it never re-evaluates anything, and a
/// non-deterministic verdict is frozen at ingest (ADR 0006).
///
/// Each verdict binds to a build by its <c>provenance.commitSha</c>, resolved to
/// a ComponentVersion under the token's project(s). Conformance is repo-level, so
/// a verdict attaches to ONE component version of the commit — the query resolves
/// the whole commit's CV set, so any single attachment is found. Upserts by
/// (build, adrRef, ruleId): a re-run replaces prior verdicts rather than
/// duplicating them.
/// </summary>
public sealed class ConformanceIngestService(FindingsDbContext db)
{
    public async Task<ConformanceIngestResult> IngestAsync(
        IReadOnlyList<Guid> candidateProjectIds,
        IReadOnlyList<ConformanceEventDto> events,
        CancellationToken ct = default)
    {
        // Keep only the conformance verdicts that carry enough to attach.
        var verdicts = events
            .Where(e => string.Equals(e.Type, BuildEventTypes.ConformanceEvaluated, StringComparison.Ordinal)
                     || string.Equals(e.Payload?.Type, BuildEventTypes.ConformanceEvaluated, StringComparison.Ordinal))
            .Select(e => e.Payload)
            .Where(p => p is not null
                     && !string.IsNullOrWhiteSpace(p.AdrRef)
                     && !string.IsNullOrWhiteSpace(p.RuleId)
                     && !string.IsNullOrWhiteSpace(p.Verdict))
            .Select(p => p!)
            .ToList();

        var totalEvents = events.Count;
        var skipped = totalEvents - verdicts.Count;

        // Resolve each distinct commit sha to one ComponentVersion under the
        // token's project(s), in a single query rather than per-verdict.
        var shas = verdicts
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

        foreach (var p in verdicts)
        {
            var sha = p.Provenance?.CommitSha;
            if (sha is null || !cvByCommit.TryGetValue(sha, out var cvId))
            {
                // No build to bind to (missing/unknown commit, or out of scope).
                skipped++;
                continue;
            }

            var existing = await db.ConformanceFindings
                .FirstOrDefaultAsync(f => f.ComponentVersionId == cvId && f.AdrRef == p.AdrRef && f.RuleId == p.RuleId, ct);

            var verdict = ParseVerdict(p.Verdict);
            var method = ParseMethod(p.Method);
            var verify = ParseVerify(p.Provenance?.VerifyVerdict, verdict);

            if (existing is null)
            {
                db.ConformanceFindings.Add(new ConformanceFinding
                {
                    ComponentVersionId = cvId,
                    AdrRef = p.AdrRef!,
                    RuleId = p.RuleId!,
                    // The producer sends no prose title; the ADR statement is the
                    // closest "claim" on a fail, the rule id otherwise.
                    Claim = p.AdrQuote is { Length: > 0 } ? p.AdrQuote : p.RuleId!,
                    Verdict = verdict,
                    Method = method,
                    AdrQuote = p.AdrQuote,
                    CodeEvidence = p.CodeEvidence,
                    Location = FormatLocation(p.Location),
                    CommitSha = sha,
                    RulesSha = p.Provenance?.RulesSha,
                    ModelId = p.Provenance?.ModelId,
                    VerifyVerdict = verify,
                    ControlRefs = p.ControlRefs ?? [],
                    ZtPillar = p.ZtPillar,
                    ZtFunction = p.ZtFunction,
                    ZtStage = p.ZtStage,
                    MandateId = p.MandateId,
                    EvaluatedAt = now,
                });
            }
            else
            {
                // Re-run for the same (build, adr, rule): the newest verdict wins,
                // frozen again. Disposition (findings-side) is left untouched.
                existing.Verdict = verdict;
                existing.Method = method;
                existing.AdrQuote = p.AdrQuote;
                existing.CodeEvidence = p.CodeEvidence;
                existing.Location = FormatLocation(p.Location);
                existing.CommitSha = sha;
                existing.RulesSha = p.Provenance?.RulesSha;
                existing.ModelId = p.Provenance?.ModelId;
                existing.VerifyVerdict = verify;
                existing.ControlRefs = p.ControlRefs ?? [];
                existing.ZtPillar = p.ZtPillar;
                existing.ZtFunction = p.ZtFunction;
                existing.ZtStage = p.ZtStage;
                existing.MandateId = p.MandateId;
                existing.EvaluatedAt = now;
            }

            accepted++;
            builds.Add(sha);
        }

        if (accepted > 0) await db.SaveChangesAsync(ct);
        return new ConformanceIngestResult(accepted, skipped, builds.ToArray());
    }

    private static string? FormatLocation(ConformanceLocationDto? loc) =>
        loc?.File is not { Length: > 0 } file ? null : loc.Line is { } line ? $"{file}:{line}" : file;

    private static ConformanceVerdict ParseVerdict(string? v) => v?.ToLowerInvariant() switch
    {
        "pass" => ConformanceVerdict.Pass,
        "fail" => ConformanceVerdict.Fail,
        "unknown" => ConformanceVerdict.Unknown,
        _ => ConformanceVerdict.Error,   // "error" and anything unrecognized fail closed
    };

    private static ConformanceMethod ParseMethod(string? m) => m?.ToLowerInvariant() switch
    {
        "semantic" => ConformanceMethod.Semantic,
        "verify" => ConformanceMethod.Verify,
        _ => ConformanceMethod.Deterministic,
    };

    // The wire carries the verify pass's own verdict string. It confirms when it
    // agrees with the finding's verdict, disputes when it disagrees, and is
    // not-run when absent.
    private static VerifyOutcome ParseVerify(string? verifyVerdict, ConformanceVerdict verdict)
    {
        if (string.IsNullOrWhiteSpace(verifyVerdict)) return VerifyOutcome.NotRun;
        return string.Equals(verifyVerdict, verdict.ToString(), StringComparison.OrdinalIgnoreCase)
            ? VerifyOutcome.Confirmed
            : VerifyOutcome.Disputed;
    }
}

/// <summary>The canonical build-event type strings (core ADR 0023). Only the one
/// we sink is named here.</summary>
internal static class BuildEventTypes
{
    public const string ConformanceEvaluated = "conformance.evaluated";
}
