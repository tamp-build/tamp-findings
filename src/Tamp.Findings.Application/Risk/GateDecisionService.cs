using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Risk;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Application.Risk;

public enum GateDecisionStatus { Ok, ProjectNotFound, NoBuilds, NoPolicy }

public sealed record BuildRef(string? CommitSha, string VersionString, DateTimeOffset LatestCreatedAt);

public sealed record GateDecisionResult(
    BuildRef Current,
    BuildRef? Prior,
    double CurrentScore,
    string CurrentBand,
    double? PriorScore,
    string? PriorBand,
    Guid PolicyId,
    string PolicyName,
    GateEvaluation Evaluation,
    EnforcementMode Mode);

// Evaluates the latest canonical build of a project against its effective risk
// policy + gates, WITH the prior canonical build for the delta-aware gates, and
// resolves the effective enforcement mode. One implementation shared by the
// cookie-authed dashboard endpoint and the bearer-authed CLI gate endpoint, so
// they cannot drift (the "9 gates enabled" bug class, applied to gating).
public sealed class GateDecisionService
{
    private readonly FindingsDbContext _db;
    private readonly RiskInputsBuilder _inputs;
    private readonly EnforcementResolver _enforcement;
    private readonly Policy.PolicyResolver _resolver;

    public GateDecisionService(FindingsDbContext db, RiskInputsBuilder inputs, EnforcementResolver enforcement, Policy.PolicyResolver resolver)
    {
        _db = db;
        _inputs = inputs;
        _enforcement = enforcement;
        _resolver = resolver;
    }

    public async Task<(GateDecisionStatus Status, GateDecisionResult? Result)> ForLatestAsync(
        Guid projectId, CancellationToken ct = default)
    {
        var project = await _db.Projects.AsNoTracking()
            .Include(p => p.Client)
            .FirstOrDefaultAsync(p => p.Id == projectId, ct);
        if (project is null) return (GateDecisionStatus.ProjectNotFound, null);

        // Canonical CV set per (Component, Flavor): most-recent canonical
        // commit's CVs, plus the second-most-recent for delta-aware gates.
        var canonical = await _db.ComponentVersions.AsNoTracking()
            .Where(v => v.Component!.ProjectId == projectId
                     && v.PullRequestRef == null
                     && (v.BranchName == null || v.BranchName == "main" || v.BranchName == "master"))
            .Select(v => new { v.Id, v.CommitSha, v.VersionString, v.CreatedAt })
            .ToListAsync(ct);
        if (canonical.Count == 0) return (GateDecisionStatus.NoBuilds, null);

        var byCommit = canonical
            .GroupBy(v => v.CommitSha ?? v.VersionString)
            .Select(g => new
            {
                CommitSha = g.First().CommitSha,
                VersionString = g.First().VersionString,
                Latest = g.Max(v => v.CreatedAt),
                CvIds = g.Select(v => v.Id).ToList(),
            })
            .OrderByDescending(g => g.Latest)
            .ToList();
        var current = byCommit[0];
        var prior = byCommit.Count > 1 ? byCommit[1] : null;

        var effectivePolicyId = project.RiskPolicyId ?? project.Client?.RiskPolicyId;
        RiskPolicy? policy = null;
        if (effectivePolicyId is { } id)
            policy = await _db.RiskPolicies.AsNoTracking().FirstOrDefaultAsync(p => p.Id == id, ct);
        policy ??= await _db.RiskPolicies.AsNoTracking().FirstOrDefaultAsync(p => p.IsDefault, ct);
        if (policy is null) return (GateDecisionStatus.NoPolicy, null);

        var currentInputs = await _inputs.BuildAsync(current.CvIds, policy.Config, projectId, ct);
        var currentResult = RiskScorer.Compute(policy.Config, currentInputs);

        RiskInputs? priorInputs = null;
        double? priorScore = null;
        string? priorBand = null;
        if (prior is not null)
        {
            priorInputs = await _inputs.BuildAsync(prior.CvIds, policy.Config, projectId, ct);
            var priorResult = RiskScorer.Compute(policy.Config, priorInputs);
            priorScore = Math.Round(priorResult.Score, 1);
            priorBand = priorResult.Band;
        }

        // The gates the build is judged against are the MERGED three-layer set
        // (ADR 0007): template → client → this project, strictest-wins. For a
        // project with no template or client layer the resolver reproduces its
        // own GatesConfig exactly, so this is behaviour-preserving; a client or
        // template gate now applies to every project under it.
        var gates = await _resolver.EffectiveGatesAsync(projectId, project.GatesConfig, ct);
        // The build's aggregate capability (TFND-184): the union across its
        // components' profiles. A conditional gate the build cannot produce
        // (DAST with no web-facing component) resolves to N/A, not a false pass.
        var capability = await AggregateCapabilityAsync(current.CvIds, ct);
        var evaluation = GateEvaluator.Evaluate(gates, currentInputs, currentResult.Score, priorInputs, priorScore, capability);

        var mode = await _enforcement.ForProjectAsync(projectId, ct);

        return (GateDecisionStatus.Ok, new GateDecisionResult(
            Current: new BuildRef(current.CommitSha, current.VersionString, current.Latest),
            Prior: prior is null ? null : new BuildRef(prior.CommitSha, prior.VersionString, prior.Latest),
            CurrentScore: Math.Round(currentResult.Score, 1),
            CurrentBand: currentResult.Band,
            PriorScore: priorScore,
            PriorBand: priorBand,
            PolicyId: policy.Id,
            PolicyName: policy.Name,
            Evaluation: evaluation,
            Mode: mode));
    }

    // The union of the build's components' capabilities (TFND-184). If any
    // component is web-facing, DAST applies to the build; if it is all libraries,
    // DAST/IaC/image are N/A. No components resolves to code-package capabilities.
    private async Task<Tamp.Findings.Domain.Compliance.ComponentCapability> AggregateCapabilityAsync(
        IReadOnlyList<Guid> cvIds, CancellationToken ct)
    {
        var profiles = await _db.ComponentVersions.AsNoTracking()
            .Where(cv => cvIds.Contains(cv.Id))
            .Select(cv => cv.Component!.Profile)
            .Distinct()
            .ToListAsync(ct);

        if (profiles.Count == 0)
            return Tamp.Findings.Domain.Compliance.ComponentProfiles.Capabilities(
                Tamp.Findings.Domain.Compliance.ComponentProfile.CodePackage);

        return profiles.Aggregate(
            Tamp.Findings.Domain.Compliance.ComponentCapability.None,
            (acc, p) => acc | Tamp.Findings.Domain.Compliance.ComponentProfiles.Capabilities(p));
    }
}
