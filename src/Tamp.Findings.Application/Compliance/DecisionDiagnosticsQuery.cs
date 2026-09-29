using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Data;

namespace Tamp.Findings.Application.Compliance;

/// <summary>
/// The undocumented-decision advisories for a build (ADR 0013), for the decisions evidence page.
/// Read-only. tamp.findings is the sink: these rows were produced by tamp-conformance's
/// reverse-examination and ingested; nothing here re-evaluates anything. Returns null when no
/// producer has run for the build (honestly "not examined", never "all documented").
/// </summary>
public sealed class DecisionDiagnosticsQuery(FindingsDbContext db)
{
    private async Task<(Guid[] CvIds, string? Sha)> ResolveCvIdsAsync(Guid projectId, string? commitSha, CancellationToken ct)
    {
        var sha = commitSha;
        if (string.IsNullOrWhiteSpace(sha))
        {
            sha = await db.ComponentVersions.AsNoTracking()
                .Where(cv => cv.ProjectId == projectId)
                .OrderByDescending(cv => cv.CreatedAt)
                .Select(cv => cv.CommitSha)
                .FirstOrDefaultAsync(ct);
        }
        if (sha is null) return ([], null);
        var ids = await db.ComponentVersions.AsNoTracking()
            .Where(cv => cv.CommitSha == sha
                && cv.ProjectId == projectId)
            .Select(cv => cv.Id)
            .ToArrayAsync(ct);
        return (ids, sha);
    }

    public async Task<DecisionReport?> ForProjectAsync(Guid projectId, string? commitSha = null, CancellationToken ct = default)
    {
        var (cvIds, sha) = await ResolveCvIdsAsync(projectId, commitSha, ct);
        if (cvIds.Length == 0) return null;

        var rows = await db.DecisionDiagnostics.AsNoTracking()
            .Where(d => cvIds.Contains(d.ComponentVersionId))
            .OrderBy(d => d.Kind).ThenBy(d => d.Location)
            .Select(d => new DecisionRow(d.Kind, d.RuleId, d.Summary, d.Location, d.ControlRefs))
            .ToListAsync(ct);

        if (rows.Count == 0) return null;

        var byKind = rows.GroupBy(r => r.Kind)
            .ToDictionary(g => g.Key, g => g.Count());
        var detectedAt = await db.DecisionDiagnostics.AsNoTracking()
            .Where(d => cvIds.Contains(d.ComponentVersionId)).MaxAsync(d => (DateTimeOffset?)d.DetectedAt, ct);

        return new DecisionReport(sha, detectedAt ?? DateTimeOffset.UtcNow, rows, byKind);
    }
}

public sealed record DecisionRow(string Kind, string RuleId, string Summary, string? Location, IReadOnlyList<string> ControlRefs);
public sealed record DecisionReport(
    string? CommitSha, DateTimeOffset DetectedAt, IReadOnlyList<DecisionRow> Decisions,
    IReadOnlyDictionary<string, int> CountsByKind);
