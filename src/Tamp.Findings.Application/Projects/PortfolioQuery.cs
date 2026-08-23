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
                    Blocking: ["never ingested a build"]));
                continue;
            }

            var config = project.RiskPolicyId is { } id && policies.TryGetValue(id, out var chosen)
                ? chosen.Config
                : defaultPolicy?.Config ?? RiskPolicyDefaults.BuildTampStandardV1();

            var ids = await _db.ComponentVersions.AsNoTracking()
                .Where(cv => cv.CommitSha == latest.CommitSha
                             && _db.Components.Any(c => c.Id == cv.ComponentId && c.ProjectId == project.Id))
                .Select(cv => cv.Id)
                .ToArrayAsync(ct);

            var inputs = await _inputs.BuildAsync(ids, config, project.Id, ct);
            var result = RiskScorer.Compute(config, inputs);
            var gates = GateEvaluator.Evaluate(
                project.GatesConfig ?? new ProjectGatesConfig(), inputs, result.Score, prior: null, priorScore: null);

            rows.Add(new PortfolioRow(
                project.Id, project.Name, project.ClientName,
                result.Score, result.Band, gates, latest.CreatedAt,
                BlockingReasons(gates, latest.CreatedAt, now)));
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
    IReadOnlyList<string> Blocking)
{
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
