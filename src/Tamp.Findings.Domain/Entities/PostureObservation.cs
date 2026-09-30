using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Domain.Entities;

/// <summary>
/// A producer-reported control-posture fact (TFND-212): the observed state of one
/// <see cref="Risk.PostureCheck"/> for a project, at the time a build ran.
///
/// It is a FACT the producer reports (tamp/CI reads the repo/org setting), not a
/// judgement — the same fact/policy split as the rest of the platform. findings
/// owns which checks exist, what they gate, and which controls they satisfy; the
/// producer just says "branch protection was on, here's the evidence."
///
/// Scoped to the PROJECT (a project maps to one repo), not the build: branch
/// protection / org 2FA are properties of the repo/org at a point in time, not of
/// a commit. Replace-on-ingest per (ProjectId, CheckId) — the latest observation
/// is the current posture.
/// </summary>
public sealed class PostureObservation
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid ProjectId { get; set; }

    /// <summary>Matches a <see cref="Risk.PostureCheck.Id"/> — e.g. "branch-protection".</summary>
    public string CheckId { get; set; } = "";

    public PostureStatus Status { get; set; }

    /// <summary>Human-readable evidence for the status: "2 approvals required; force-push blocked".</summary>
    public string? Detail { get; set; }

    /// <summary>Who observed it — "tamp/github-actions", "gh-api", etc.</summary>
    public string? Source { get; set; }

    /// <summary>When the producer read the setting (its own clock).</summary>
    public DateTimeOffset ObservedAt { get; set; }

    public DateTimeOffset IngestedAt { get; set; } = DateTimeOffset.UtcNow;

    public Project? Project { get; set; }
}
