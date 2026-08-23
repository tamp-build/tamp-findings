using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Application.Risk;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Risk;

namespace Tamp.Findings.Application.Projects;

/// <summary>
/// Everything the project hub renders, computed once.
///
/// The hub shows the score, its per-category breakdown and the gate verdicts
/// side by side, and the hand-off is emphatic that they must agree: the "9
/// gates enabled" line that contradicted a computed 10 was a DTO-drift bug,
/// and "sharing the domain types directly with the UI" is the reason the port
/// is worth doing at all.
///
/// So this returns the domain types — <see cref="RiskResult"/> and
/// <see cref="GateEvaluation"/> — rather than flattened DTOs. There is nothing
/// between the scorer and the screen to drift.
/// </summary>
public sealed class ProjectHubQuery
{
    private readonly FindingsDbContext _db;
    private readonly RiskInputsBuilder _inputs;

    public ProjectHubQuery(FindingsDbContext db, RiskInputsBuilder inputs)
    {
        _db = db;
        _inputs = inputs;
    }

    /// <summary>
    /// Resolve a project from its client and project slugs.
    ///
    /// Slugs are what the URL carries, and they are matched case-insensitively
    /// because a link pasted from a chat window should not 404 on capitals.
    /// </summary>
    /// <summary>
    /// Turn a client/project pair of names into a reference, if the reader may
    /// see it (TFND-133).
    ///
    /// THE choke point for the whole UI: every project screen starts here, and
    /// a null return makes the entire subtree unreachable by URL. That is why
    /// the visible set is a required parameter rather than an optional one —
    /// a caller that forgot to pass it would otherwise silently get everything,
    /// which is precisely the defect this closes.
    ///
    /// Returns null rather than throwing for a project outside the boundary, so
    /// the screen renders "no such project". Distinguishing "not yours" from
    /// "does not exist" would confirm that another tenant has a project by that
    /// name, which is the one bit worth withholding.
    /// </summary>
    public async Task<ProjectRef?> ResolveAsync(
        string clientSlug, string projectSlug, VisibleSet visible, CancellationToken ct = default)
    {
        var found = await (
            from p in _db.Projects.AsNoTracking()
            join c in _db.Clients.AsNoTracking() on p.ClientId equals c.Id
            where EF.Functions.ILike(c.Name, clientSlug) && EF.Functions.ILike(p.Name, projectSlug)
            select new ProjectRef(c.Id, c.Name, p.Id, p.Name, p.RiskPolicyId, p.GatesConfig))
            .FirstOrDefaultAsync(ct);

        if (found is null) return null;

        if (visible.CanSeeProject(found.ClientId, found.ProjectId)) return found;

        // A component-level grant makes the project reachable as the container
        // for that component, but no wider. Without this, somebody granted a
        // role on one component could not open the project it lives in.
        var componentIds = await _db.Components.AsNoTracking()
            .Where(c => c.ProjectId == found.ProjectId)
            .Select(c => c.Id)
            .ToArrayAsync(ct);

        return componentIds.Any(visible.Components.Contains) ? found : null;
    }

    /// <summary>
    /// Score and gates for a build, or for the latest canonical build when
    /// <paramref name="commitSha"/> is null.
    ///
    /// Returns null when the project has no canonical build at all. That is a
    /// real and common state — a project registered but never scanned — and the
    /// hub has to render it as "no scan" rather than as a zero score, because
    /// "a project with a green score and no recent scan is not healthy".
    /// </summary>
    public async Task<ProjectHubData?> LoadAsync(ProjectRef project, string? commitSha, CancellationToken ct = default)
    {
        var policy = await ResolvePolicyAsync(project, ct);

        var builds = await _db.ComponentVersions.AsNoTracking()
            .Where(cv => _db.Components.Any(c => c.Id == cv.ComponentId && c.ProjectId == project.ProjectId))
            .OrderByDescending(cv => cv.CreatedAt)
            .Take(50)
            .ToArrayAsync(ct);

        if (builds.Length == 0) return null;

        var selected = commitSha is null
            ? builds
            : builds.Where(b => b.CommitSha != null && b.CommitSha.StartsWith(commitSha, StringComparison.OrdinalIgnoreCase)).ToArray();

        if (selected.Length == 0) return null;

        // The build under inspection is every component version sharing that
        // commit — a commit can produce several builds distinguished by flavor
        // (net10, web, deployed), and the hub scores the commit, not one flavor.
        var head = selected[0];
        var cvIds = selected.Where(b => b.CommitSha == head.CommitSha).Select(b => b.Id).ToArray();

        var inputs = await _inputs.BuildAsync(cvIds, policy.Config, project.ProjectId, ct);
        var result = RiskScorer.Compute(policy.Config, inputs);

        // TFND-134. The images this commit produced, worst base first — the
        // one somebody has to act on. Null when nothing was inspected, which
        // the card renders as "not inspected" rather than as an empty list.
        var images = (await _db.ContainerImages.AsNoTracking()
                .Where(i => cvIds.Contains(i.ComponentVersionId))
                .Select(i => new
                {
                    i.Reference, i.Digest, i.CreatedAt, i.OsFamily, i.OsVersion,
                    i.BaseImageReference, i.BaseImageDigest, i.BaseImageCreatedAt, i.InspectedAt,
                })
                .ToArrayAsync(ct))
            .Select(i => new ContainerImageRow(
                i.Reference, i.Digest, i.CreatedAt, i.OsFamily, i.OsVersion,
                i.BaseImageReference, i.BaseImageDigest, i.BaseImageCreatedAt,
                i.BaseImageCreatedAt is { } baseCreated
                    ? Math.Max(0, (int)(i.InspectedAt - baseCreated).TotalDays)
                    : null))
            .OrderByDescending(i => i.BaseImageAgeInDays ?? -1)
            .ThenBy(i => i.Reference, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        // Prior build, for the deltas the hub shows when they are switched on.
        var priorSha = builds.Select(b => b.CommitSha).Distinct()
            .SkipWhile(s => s == head.CommitSha).FirstOrDefault();

        RiskInputs? priorInputs = null;
        double? priorScore = null;
        if (priorSha is not null)
        {
            var priorIds = builds.Where(b => b.CommitSha == priorSha).Select(b => b.Id).ToArray();
            priorInputs = await _inputs.BuildAsync(priorIds, policy.Config, project.ProjectId, ct);
            priorScore = RiskScorer.Compute(policy.Config, priorInputs).Score;
        }

        // An unconfigured project has every gate disabled, which reads as
        // "clear to ship" with zero enabled gates — honest, and visibly
        // different from "all gates passing".
        var gateConfig = project.GatesConfig ?? new ProjectGatesConfig();
        var gates = GateEvaluator.Evaluate(gateConfig, inputs, result.Score, priorInputs, priorScore);

        var history = await BuildHistoryAsync(project, policy.Config, gateConfig, builds, ct);

        return new ProjectHubData(project, head.CommitSha, head.VersionString, head.CreatedAt,
            policy.Name, result, gates, inputs, history, images);
    }

    /// <summary>
    /// The last few canonical builds, each scored and gated.
    ///
    /// Capped at six on purpose. This is the one genuinely expensive part of
    /// the hub — every row is a full RiskInputs build plus a scorer and gate
    /// pass — and the design asks for six. Raising the cap makes the hub
    /// quadratically slower on projects with long histories, which is exactly
    /// the projects whose history is worth reading.
    /// </summary>
    private async Task<IReadOnlyList<BuildHistoryRow>> BuildHistoryAsync(
        ProjectRef project,
        RiskPolicyConfig config,
        ProjectGatesConfig gateConfig,
        IReadOnlyList<Domain.Entities.ComponentVersion> builds,
        CancellationToken ct)
    {
        var shas = builds
            .Select(b => b.CommitSha)
            .Where(s => s is not null)
            .Distinct()
            .Take(6)
            .ToArray();

        var rows = new List<BuildHistoryRow>(shas.Length);
        double? previousScore = null;

        // Oldest first so each row's delta is against the build before it, then
        // reversed for display — newest at the top is what a reader scans.
        foreach (var sha in shas.Reverse())
        {
            var ids = builds.Where(b => b.CommitSha == sha).Select(b => b.Id).ToArray();
            var inputs = await _inputs.BuildAsync(ids, config, project.ProjectId, ct);
            var scored = RiskScorer.Compute(config, inputs);
            var gates = GateEvaluator.Evaluate(gateConfig, inputs, scored.Score, prior: null, priorScore: previousScore);

            var head = builds.First(b => b.CommitSha == sha);
            rows.Add(new BuildHistoryRow(
                sha!, head.BranchName, head.VersionString, head.CreatedAt,
                scored.Score, previousScore is null ? null : scored.Score - previousScore,
                inputs.CoverageMeasured ? inputs.SequenceCoveragePercent : null,
                gates));

            previousScore = scored.Score;
        }

        rows.Reverse();
        return rows;
    }

    private async Task<(string Name, RiskPolicyConfig Config)> ResolvePolicyAsync(
        ProjectRef project, CancellationToken ct)
    {
        var policy = project.RiskPolicyId is { } id
            ? await _db.RiskPolicies.AsNoTracking().FirstOrDefaultAsync(p => p.Id == id, ct)
            : await _db.RiskPolicies.AsNoTracking().FirstOrDefaultAsync(p => p.IsDefault, ct);

        // No policy at all should be impossible — Program.cs seeds one on
        // startup — but falling back to the built-in defaults is better than
        // throwing on a screen whose whole job is to tell someone what their
        // posture is.
        return policy is null
            ? ("Tamp Standard v1", RiskPolicyDefaults.BuildTampStandardV1())
            : (policy.Name, policy.Config);
    }
}

/// <summary>
/// A project located from its URL slugs.
///
/// Gates hang off the PROJECT, not the policy — a policy defines how to score,
/// the project decides what blocks a release with it. Two projects can share
/// Tamp Standard v1 and gate differently.
/// </summary>
public sealed record ProjectRef(
    Guid ClientId, string ClientName, Guid ProjectId, string ProjectName,
    Guid? RiskPolicyId, ProjectGatesConfig? GatesConfig);

/// <summary>
/// The hub's data, in domain types.
///
/// Deliberately NOT flattened into DTOs: the score, its breakdown and the gate
/// verdicts have to agree with each other on screen, and every flattening step
/// is somewhere they could stop agreeing.
/// </summary>
public sealed record ProjectHubData(
    ProjectRef Project,
    string? CommitSha,
    string VersionString,
    DateTimeOffset BuiltAt,
    string PolicyName,
    RiskResult Risk,
    GateEvaluation Gates,
    RiskInputs Inputs,
    IReadOnlyList<BuildHistoryRow> History,
    /// <summary>Images this commit produced (TFND-134). Empty when none was inspected.</summary>
    IReadOnlyList<ContainerImageRow> Images);

/// <summary>
/// One image a build produced, and the base image behind it (TFND-134).
///
/// Age is measured at the BUILD rather than against today, so the number does
/// not drift upward every time somebody opens the page. "The base image was 400
/// days old when we shipped this" is a fact about the release.
/// </summary>
public sealed record ContainerImageRow(
    string Reference,
    string? Digest,
    DateTimeOffset? CreatedAt,
    string? OsFamily,
    string? OsVersion,
    string? BaseImageReference,
    string? BaseImageDigest,
    DateTimeOffset? BaseImageCreatedAt,
    int? BaseImageAgeInDays);

/// <summary>
/// One row of the build-history table. Carries the whole GateEvaluation rather
/// than a pass/fail tally, because the tally has three parts now and
/// reconstructing it from two would drop every Unknown.
/// </summary>
public sealed record BuildHistoryRow(
    string CommitSha,
    string? Branch,
    string VersionString,
    DateTimeOffset IngestedAt,
    double Score,
    double? Delta,
    double? CoveragePercent,
    GateEvaluation Gates);
