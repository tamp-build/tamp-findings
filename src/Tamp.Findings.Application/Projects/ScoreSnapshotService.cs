using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Application.Risk;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Risk;

namespace Tamp.Findings.Application.Projects;

/// <summary>
/// Writes a build's <see cref="ScoreSnapshot"/> at ingest (TFND-176): evidence lands → rescore
/// the whole commit under the project's current policy → upsert one snapshot per (project, commit).
/// The portfolio trend and per-build history then read the score back instead of recomputing a
/// full RiskInputs + scorer pass per point on every view.
///
/// Scores the WHOLE commit (all its component versions), exactly as PortfolioQuery/ProjectHubQuery
/// do, so the stored score matches what a live read would compute.
/// </summary>
public sealed class ScoreSnapshotService(FindingsDbContext db, RiskInputsBuilder inputs, Risk.ScoringPolicyResolver scoring)
{
    /// <summary>Snapshot the build a component version belongs to. The uniform ingest hook —
    /// each ingest endpoint has a resolved CV in hand. No-ops when the build has no commit sha.</summary>
    public async Task RecordForBuildAsync(Guid componentVersionId, CancellationToken ct = default)
    {
        var cv = await db.ComponentVersions.AsNoTracking()
            .Where(v => v.Id == componentVersionId)
            .Select(v => new { v.CommitSha, ProjectId = v.ProjectId })
            .FirstOrDefaultAsync(ct);
        if (cv is null || string.IsNullOrWhiteSpace(cv.CommitSha)) return;
        await RecordForCommitAsync(cv.ProjectId, cv.CommitSha!, ct);
    }

    public async Task RecordForCommitAsync(Guid projectId, string commitSha, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(commitSha)) return;

        var cvs = await db.ComponentVersions.AsNoTracking()
            .Where(v => v.CommitSha == commitSha
                && v.ProjectId == projectId)
            .Select(v => new { v.Id, v.CreatedAt })
            .ToListAsync(ct);
        if (cvs.Count == 0) return;

        var ids = cvs.Select(x => x.Id).ToArray();
        var builtAt = cvs.Max(x => x.CreatedAt);
        var (config, policyName) = await ResolvePolicyAsync(projectId, ct);

        var built = await inputs.BuildAsync(ids, config, projectId, ct);
        var result = RiskScorer.Compute(config, built);
        var breakdown = result.Breakdown.ToDictionary(x => x.Key, x => x.Contribution);
        var coverage = built.CoverageMeasured ? built.SequenceCoveragePercent : (double?)null;
        var now = DateTimeOffset.UtcNow;

        var snap = await db.ScoreSnapshots
            .FirstOrDefaultAsync(s => s.ProjectId == projectId && s.CommitSha == commitSha, ct);
        if (snap is null)
        {
            db.ScoreSnapshots.Add(new ScoreSnapshot
            {
                ProjectId = projectId, CommitSha = commitSha,
                Score = result.Score, Band = result.Band, CoveragePercent = coverage,
                Breakdown = breakdown, BuiltAt = builtAt, ComputedAt = now, PolicyName = policyName,
            });
        }
        else
        {
            snap.Score = result.Score; snap.Band = result.Band; snap.CoveragePercent = coverage;
            snap.Breakdown = breakdown; snap.BuiltAt = builtAt; snap.ComputedAt = now; snap.PolicyName = policyName;
        }
        await db.SaveChangesAsync(ct);
    }

    private async Task<(RiskPolicyConfig Config, string Name)> ResolvePolicyAsync(Guid projectId, CancellationToken ct)
    {
        var resolved = await scoring.ForProjectAsync(projectId, ct);
        return (resolved.Config, resolved.Name);
    }
}
