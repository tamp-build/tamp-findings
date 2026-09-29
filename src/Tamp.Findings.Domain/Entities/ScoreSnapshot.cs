namespace Tamp.Findings.Domain.Entities;

/// <summary>
/// A build's risk score, frozen when the build was scored (TFND-176). The portfolio trend and
/// the per-build history recomputed a full RiskInputs + scorer pass for every point on every
/// view — bounded only by a hard cap on how many builds a trend would show. A snapshot per
/// (project, commit) removes that cost: it is written at ingest (evidence lands → rescore →
/// upsert) and read back cheaply, so a trend is a lookup, not a re-score.
///
/// One row per (ProjectId, CommitSha), upserted — the latest evidence for a build wins. The
/// score is only reused for a trend when it was computed under the SAME policy that is in force
/// now (PolicyName); a policy change makes prior snapshots fall back to a live recompute, so the
/// trend never silently mixes scores from two policies.
/// </summary>
public sealed class ScoreSnapshot
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public Guid ProjectId { get; set; }
    /// <summary>The build's commit. Unique per project — the snapshot is the whole commit's score,
    /// not one component version's.</summary>
    public required string CommitSha { get; set; }

    public double Score { get; set; }
    public string? Band { get; set; }
    public double? CoveragePercent { get; set; }

    /// <summary>Per-category contribution (key → points cost), so a category-detail trend can read
    /// one category out of the snapshot without recomputing.</summary>
    public Dictionary<string, double> Breakdown { get; set; } = new();

    /// <summary>The build's representative timestamp (max CreatedAt across the commit's CVs) — the
    /// ordering axis for a trend, distinct from when the score was computed.</summary>
    public DateTimeOffset BuiltAt { get; set; }
    public DateTimeOffset ComputedAt { get; set; } = DateTimeOffset.UtcNow;

    /// <summary>The risk policy the score was computed under. A trend reuses the snapshot only
    /// while this matches the project's current policy.</summary>
    public string PolicyName { get; set; } = "";
}
