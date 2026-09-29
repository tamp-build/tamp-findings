using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Compliance;

namespace Tamp.Findings.Application.Compliance;

/// <summary>
/// The ADR-conformance verdicts for a build (ADR 0006), for the conformance
/// evidence page. Read-only. tamp.findings is the sink: these rows were produced
/// by CI in the governed repo and ingested; nothing here re-evaluates anything.
/// Returns null when no producer has run for the build — an absent report is
/// honestly "not scanned", never a pass.
/// </summary>
public sealed class ConformanceQuery(FindingsDbContext db)
{
    private async Task<Guid[]> ResolveCvIdsAsync(Guid projectId, string? commitSha, CancellationToken ct)
    {
        var sha = commitSha;
        if (string.IsNullOrWhiteSpace(sha))
        {
            sha = await db.ComponentVersions.AsNoTracking()
                .Where(cv => db.Components.Any(c => c.Id == cv.ComponentId && c.ProjectId == projectId))
                .OrderByDescending(cv => cv.CreatedAt)
                .Select(cv => cv.CommitSha)
                .FirstOrDefaultAsync(ct);
        }
        if (sha is null) return [];
        return await db.ComponentVersions.AsNoTracking()
            .Where(cv => cv.CommitSha == sha
                && db.Components.Any(c => c.Id == cv.ComponentId && c.ProjectId == projectId))
            .Select(cv => cv.Id)
            .ToArrayAsync(ct);
    }

    public async Task<ConformanceReport?> ForProjectAsync(Guid projectId, string? commitSha, CancellationToken ct = default)
    {
        var cvIds = await ResolveCvIdsAsync(projectId, commitSha, ct);
        if (cvIds.Length == 0) return null;

        var findings = await db.ConformanceFindings.AsNoTracking()
            .Where(f => cvIds.Contains(f.ComponentVersionId))
            // Blocking verdicts first (Fail, Unknown, Error), then by ADR/rule.
            .OrderByDescending(f => f.Verdict != ConformanceVerdict.Pass)
            .ThenBy(f => f.AdrRef).ThenBy(f => f.RuleId)
            .ToListAsync(ct);

        if (findings.Count == 0) return null;

        var now = DateTimeOffset.UtcNow;
        var rows = findings.Select(f => new ConformanceFindingRow(
            f.Id, f.AdrRef, f.RuleId, f.Claim, f.Verdict, f.Method, f.AdrQuote, f.CodeEvidence, f.Location,
            f.ModelId, f.VerifyVerdict, f.ControlRefs, f.Dispositioned, f.DispositionJustification,
            f.DispositionedByLogin, f.DispositionExpiry, f.Blocks(now))).ToArray();

        var controlCounts = findings
            .SelectMany(f => f.ControlRefs)
            .GroupBy(c => c)
            .ToDictionary(g => g.Key, g => g.Count());

        var first = findings[0];
        return new ConformanceReport(
            Pass: findings.Count(f => f.Verdict == ConformanceVerdict.Pass),
            Fail: findings.Count(f => f.Verdict == ConformanceVerdict.Fail),
            Unknown: findings.Count(f => f.Verdict == ConformanceVerdict.Unknown),
            Error: findings.Count(f => f.Verdict == ConformanceVerdict.Error),
            Dispositioned: findings.Count(f => f.Dispositioned),
            CommitSha: first.CommitSha,
            RulesSha: first.RulesSha,
            EvaluatedAt: findings.Max(f => f.EvaluatedAt),
            Deterministic: findings.Count(f => f.Method == ConformanceMethod.Deterministic),
            Semantic: findings.Count(f => f.Method == ConformanceMethod.Semantic),
            Findings: rows,
            ControlCounts: controlCounts);
    }
}

public sealed record ConformanceFindingRow(
    Guid Id, string AdrRef, string RuleId, string Claim, ConformanceVerdict Verdict, ConformanceMethod Method,
    string? AdrQuote, string? CodeEvidence, string? Location, string? ModelId, VerifyOutcome VerifyVerdict,
    IReadOnlyList<string> ControlRefs, bool Dispositioned, string? DispositionJustification,
    string? DispositionedByLogin, DateTimeOffset? DispositionExpiry, bool Blocks);

public sealed record ConformanceReport(
    int Pass, int Fail, int Unknown, int Error, int Dispositioned,
    string? CommitSha, string? RulesSha, DateTimeOffset EvaluatedAt,
    int Deterministic, int Semantic,
    IReadOnlyList<ConformanceFindingRow> Findings,
    IReadOnlyDictionary<string, int> ControlCounts);
