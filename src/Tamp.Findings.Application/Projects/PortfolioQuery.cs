using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Application.Risk;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Risk;

namespace Tamp.Findings.Application.Projects;

/// <summary>
/// The security lead's weekly question: which project is worst right now.
///
/// Ordering is WORST-POSTURE-FIRST, and staleness is a first-class blocking
/// reason — "a project with a green score and no recent scan is not healthy".
/// A portfolio sorted by score alone would put the project nobody has scanned
/// in months at the top of the healthy list.
/// </summary>
public sealed class PortfolioQuery
{
    /// <summary>
    /// How long a project can go without a canonical build before that is
    /// itself the finding. Thirty days is the design's example ("no canonical
    /// build in 41 days"); it is a judgement call and belongs in instance
    /// settings when TFND-113 lands.
    /// </summary>
    public static readonly TimeSpan StaleAfter = TimeSpan.FromDays(30);

    private readonly FindingsDbContext _db;
    private readonly RiskInputsBuilder _inputs;

    public PortfolioQuery(FindingsDbContext db, RiskInputsBuilder inputs)
    {
        _db = db;
        _inputs = inputs;
    }

    /// <summary>
    /// Every project the reader may see, scored (TFND-133).
    ///
    /// The visible set is required rather than optional. An optional one
    /// defaults to "no filter" when a caller forgets, and on the screen that
    /// lists every project in the estate that is the whole defect.
    /// </summary>
    public async Task<IReadOnlyList<PortfolioRow>> LoadAsync(
        VisibleSet visible, CancellationToken ct = default)
    {
        if (visible.IsEmpty) return [];

        var candidates = await (
            from p in _db.Projects.AsNoTracking()
            join c in _db.Clients.AsNoTracking() on p.ClientId equals c.Id
            orderby c.Name, p.Name
            select new
            {
                p.Id, p.Name, ClientName = c.Name, p.ClientId, p.RiskPolicyId, p.GatesConfig,
            })
            .ToArrayAsync(ct);

        // Component-tier grants make their project visible as a container, so
        // the filter cannot be answered from the project row alone. Loaded once
        // rather than per project.
        var componentsByProject = visible.Unrestricted || visible.Components.Count == 0
            ? []
            : await _db.Components.AsNoTracking()
                .Where(c => visible.Components.Contains(c.Id))
                .Select(c => c.ProjectId)
                .Distinct()
                .ToArrayAsync(ct);

        var reachableByComponent = componentsByProject.ToHashSet();

        var projects = candidates
            .Where(p => visible.CanSeeProject(p.ClientId, p.Id) || reachableByComponent.Contains(p.Id))
            .ToArray();

        var defaultPolicy = await _db.RiskPolicies.AsNoTracking().FirstOrDefaultAsync(p => p.IsDefault, ct);
        var policies = await _db.RiskPolicies.AsNoTracking().ToDictionaryAsync(p => p.Id, ct);

        var rows = new List<PortfolioRow>(projects.Length);
        var now = DateTimeOffset.UtcNow;

        foreach (var project in projects)
        {
            // Latest build per project. One query per project is honest about
            // what this screen costs — it scores every project in the estate —
            // and the alternative, one giant join, would still do the same
            // scoring work while being far harder to read.
            var latest = await _db.ComponentVersions.AsNoTracking()
                .Where(cv => _db.Components.Any(c => c.Id == cv.ComponentId && c.ProjectId == project.Id))
                .OrderByDescending(cv => cv.CreatedAt)
                .FirstOrDefaultAsync(ct);

            if (latest is null)
            {
                // Never scanned at all. Not a zero score — an absence.
                rows.Add(new PortfolioRow(
                    project.Id, project.Name, project.ClientName,
                    Score: null, Band: null, Gates: null, LastBuild: null,
                    Blocking: ["never ingested a build"], Trend: []));
                continue;
            }

            // Resolve config AND name together — the trend reuses a snapshot only when its
            // PolicyName matches, and the snapshot service names the policy the same way.
            RiskPolicyConfig config;
            string policyName;
            if (project.RiskPolicyId is { } id && policies.TryGetValue(id, out var chosen))
                (config, policyName) = (chosen.Config, chosen.Name);
            else if (defaultPolicy is not null)
                (config, policyName) = (defaultPolicy.Config, defaultPolicy.Name);
            else
                (config, policyName) = (RiskPolicyDefaults.BuildTampStandardV1(), "Tamp Standard v1");

            var ids = await _db.ComponentVersions.AsNoTracking()
                .Where(cv => cv.CommitSha == latest.CommitSha
                             && _db.Components.Any(c => c.Id == cv.ComponentId && c.ProjectId == project.Id))
                .Select(cv => cv.Id)
                .ToArrayAsync(ct);

            var inputs = await _inputs.BuildAsync(ids, config, project.Id, ct);
            var result = RiskScorer.Compute(config, inputs);
            var gates = GateEvaluator.Evaluate(
                project.GatesConfig ?? new ProjectGatesConfig(), inputs, result.Score, prior: null, priorScore: null);

            var trend = await ComputeTrendAsync(project.Id, config, policyName, now, ct);

            rows.Add(new PortfolioRow(
                project.Id, project.Name, project.ClientName,
                result.Score, result.Band, gates, latest.CreatedAt,
                BlockingReasons(gates, latest.CreatedAt, now), trend));
        }

        // Worst first. Never-scanned outranks everything with a score, because
        // an unmeasured project is not a healthy one — it is an unanswered
        // question, and the design puts it above a merely bad score.
        return rows
            .OrderByDescending(r => r.Ship == ShipState.NoScan)
            .ThenByDescending(r => r.Ship == ShipState.Blocked)
            .ThenByDescending(r => r.Score ?? 0)
            .ToArray();
    }

    /// <summary>
    /// Cap on trend points shown per project. A persisted per-build snapshot
    /// (TFND-176) means most points are now a cheap lookup; only builds without
    /// a current-policy snapshot fall back to a live RiskInputs + scorer pass,
    /// so this cap bounds that worst case rather than every point.
    /// </summary>
    private const int TrendMaxPoints = 12;

    /// <summary>
    /// Scores of the recent CANONICAL builds inside the staleness window, OLDEST
    /// first, for the portfolio sparkline. Reads each build's persisted snapshot
    /// (TFND-176) when it was scored under the policy in force now; falls back to
    /// a live re-score for any build without a matching snapshot, so behaviour is
    /// unchanged and the cache fills in as builds ingest. Fewer than two canonical
    /// builds returns empty — a single point is not a trend.
    /// </summary>
    private async Task<IReadOnlyList<double>> ComputeTrendAsync(
        Guid projectId, RiskPolicyConfig config, string policyName, DateTimeOffset now, CancellationToken ct)
    {
        var windowStart = now - StaleAfter;

        // One representative timestamp per canonical commit in the window,
        // newest first, capped.
        var commits = await _db.ComponentVersions.AsNoTracking()
            .Where(cv => cv.CommitSha != null
                && cv.PullRequestRef == null
                && (cv.BranchName == null || cv.BranchName == "main" || cv.BranchName == "master")
                && cv.CreatedAt >= windowStart
                && _db.Components.Any(c => c.Id == cv.ComponentId && c.ProjectId == projectId))
            .GroupBy(cv => cv.CommitSha!)
            .Select(g => new { Commit = g.Key, At = g.Max(x => x.CreatedAt) })
            .OrderByDescending(x => x.At)
            .Take(TrendMaxPoints)
            .ToArrayAsync(ct);

        if (commits.Length < 2) return [];

        // Snapshots for these commits, computed under the CURRENT policy — the only
        // ones safe to reuse (a policy change is a different score).
        var commitKeys = commits.Select(c => c.Commit).ToArray();
        var snapshots = await _db.ScoreSnapshots.AsNoTracking()
            .Where(s => s.ProjectId == projectId && commitKeys.Contains(s.CommitSha) && s.PolicyName == policyName)
            .ToDictionaryAsync(s => s.CommitSha, s => s.Score, ct);

        // Score oldest-first so the sparkline reads left (past) to right (now).
        var scores = new List<double>(commits.Length);
        foreach (var commit in commits.OrderBy(x => x.At))
        {
            if (snapshots.TryGetValue(commit.Commit, out var snapped)) { scores.Add(snapped); continue; }

            var ids = await _db.ComponentVersions.AsNoTracking()
                .Where(cv => cv.CommitSha == commit.Commit
                    && _db.Components.Any(c => c.Id == cv.ComponentId && c.ProjectId == projectId))
                .Select(cv => cv.Id)
                .ToArrayAsync(ct);
            if (ids.Length == 0) continue;
            var inputs = await _inputs.BuildAsync(ids, config, projectId, ct);
            scores.Add(RiskScorer.Compute(config, inputs).Score);
        }

        return scores.Count >= 2 ? scores : [];
    }

    /// <summary>
    /// Named in prose, because "3 blocking" tells a security lead nothing they
    /// can act on. Staleness sits alongside the gate failures rather than in a
    /// separate column: it blocks for the same reason they do.
    /// </summary>
    private static IReadOnlyList<string> BlockingReasons(
        GateEvaluation gates, DateTimeOffset lastBuild, DateTimeOffset now)
    {
        var reasons = new List<string>();

        foreach (var gate in gates.Results.Where(r => r.Blocks))
        {
            reasons.Add(gate.Verdict == GateVerdict.Unknown
                ? $"{gate.Key} unanswered — {gate.Observed}"
                : gate.Observed);
        }

        var age = now - lastBuild;
        if (age > StaleAfter) reasons.Add($"no canonical build in {(int)age.TotalDays} days");

        return reasons;
    }
}

public enum ShipState { Clear, Blocked, NoScan }

public sealed record PortfolioRow(
    Guid ProjectId,
    string ProjectName,
    string ClientName,
    double? Score,
    string? Band,
    GateEvaluation? Gates,
    DateTimeOffset? LastBuild,
    IReadOnlyList<string> Blocking,
    // Scores of the recent canonical builds inside the 30-day window, OLDEST
    // first. Drives the portfolio sparkline. Fewer than two points renders as
    // "no scans" — a single dot is not a trend. Computed live today; see the
    // score-snapshot ticket for the scale fix.
    IReadOnlyList<double> Trend)
{
    /// <summary>
    /// Signed change across the trend window (last − first). Lower is better,
    /// so a negative delta is an improvement. Null when there are not two
    /// points to compare.
    /// </summary>
    public double? TrendDelta => Trend.Count >= 2 ? Trend[^1] - Trend[0] : null;

    /// <summary>
    /// Three states, matching the project hub's verdict chip. Derived rather
    /// than stored so the two screens cannot disagree about the same project.
    /// </summary>
    public ShipState Ship =>
        Gates is null ? ShipState.NoScan
        : Blocking.Count > 0 ? ShipState.Blocked
        : ShipState.Clear;

    public bool IsStale => LastBuild is { } at && DateTimeOffset.UtcNow - at > PortfolioQuery.StaleAfter;
}
