using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Api.Services;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Risk;

namespace Tamp.Findings.Api.Endpoints;

public sealed record BuildEvaluationResponse(
    BuildPointer Current,
    BuildPointer? Prior,
    double CurrentScore,
    string CurrentBand,
    double? PriorScore,
    string? PriorBand,
    double? DeltaPoints,
    Guid PolicyId,
    string PolicyName,
    IReadOnlyList<GateResultDto> Gates,
    int GatesEnabled,
    int GatesPassed,
    int GatesFailed);

public sealed record BuildPointer(
    string? CommitSha,
    string VersionString,
    DateTimeOffset LatestCreatedAt);

public sealed record GateResultDto(
    string Key, bool Enabled, bool Passed,
    string Observed, double? Threshold, string? Reason);

// Evaluates the *latest canonical* build of a project against its
// effective risk policy + per-project gates. Today this is the only
// evaluation surface; per-historical-build evaluation lands when we
// add the risk-delta column on the receipts panel — same builder will
// drive it.
public static class BuildEvaluationEndpoints
{
    public static IEndpointRouteBuilder MapBuildEvaluation(this IEndpointRouteBuilder app)
    {
        app.MapGet("/projects/{projectId:guid}/build-evaluation", EvaluateAsync)
           .WithName("EvaluateLatestBuild")
           .WithTags("Risk")
           .WithSummary("Risk score + per-gate pass/fail for the latest canonical build of a project. Includes the prior canonical build's score for delta-aware gates (risk regression, coverage regression).");
        return app;
    }

    private static async Task<IResult> EvaluateAsync(
        Guid projectId,
        FindingsDbContext db,
        RiskInputsBuilder inputsBuilder,
        CancellationToken ct)
    {
        var project = await db.Projects.AsNoTracking()
            .Include(p => p.Client)
            .FirstOrDefaultAsync(p => p.Id == projectId, ct);
        if (project is null) return Results.NotFound("project not found");

        // Pull the canonical CV-set per (Component, Flavor) — one row per
        // most-recent canonical commit's CVs. Plus the SECOND-most-recent
        // canonical commit's set for delta-aware gates.
        var canonical = await db.ComponentVersions.AsNoTracking()
            .Where(v => v.Component!.ProjectId == projectId
                     && v.PullRequestRef == null
                     && (v.BranchName == null || v.BranchName == "main" || v.BranchName == "master"))
            .OrderByDescending(v => v.CreatedAt)
            .Select(v => new { v.Id, v.CommitSha, v.VersionString, v.CreatedAt, v.ComponentId, v.FlavorId })
            .ToListAsync(ct);
        if (canonical.Count == 0)
            return Results.NotFound("no canonical builds for this project");

        // Group CVs into "build cycles" by commit; latest commit first.
        var byCommit = canonical
            .GroupBy(v => v.CommitSha ?? v.VersionString)
            .Select(g => new
            {
                Key = g.Key,
                CommitSha = g.First().CommitSha,
                VersionString = g.First().VersionString,
                Latest = g.Max(v => v.CreatedAt),
                CvIds = g.Select(v => v.Id).ToList(),
            })
            .OrderByDescending(g => g.Latest)
            .ToList();
        var currentBuild = byCommit[0];
        var priorBuild = byCommit.Count > 1 ? byCommit[1] : null;

        // Resolve effective policy: Project > Client > Default.
        var effectivePolicyId = project.RiskPolicyId ?? project.Client?.RiskPolicyId;
        RiskPolicy? policy = null;
        if (effectivePolicyId is { } id)
            policy = await db.RiskPolicies.AsNoTracking().FirstOrDefaultAsync(p => p.Id == id, ct);
        policy ??= await db.RiskPolicies.AsNoTracking().FirstOrDefaultAsync(p => p.IsDefault, ct);
        if (policy is null) return Results.Conflict("no default risk policy seeded");

        var currentInputs = await inputsBuilder.BuildAsync(currentBuild.CvIds, policy.Config, ct);
        var currentResult = RiskScorer.Compute(policy.Config, currentInputs);

        RiskInputs? priorInputs = null;
        double? priorScore = null;
        string? priorBand = null;
        if (priorBuild is not null)
        {
            priorInputs = await inputsBuilder.BuildAsync(priorBuild.CvIds, policy.Config, ct);
            var priorResult = RiskScorer.Compute(policy.Config, priorInputs);
            priorScore = Math.Round(priorResult.Score, 1);
            priorBand = priorResult.Band;
        }

        var gates = project.GatesConfig ?? ProjectGatesDefaults.Empty();
        var evaluation = GateEvaluator.Evaluate(
            gates, currentInputs, currentResult.Score, priorInputs, priorScore);

        return Results.Ok(new BuildEvaluationResponse(
            Current: new BuildPointer(currentBuild.CommitSha, currentBuild.VersionString, currentBuild.Latest),
            Prior: priorBuild is null ? null : new BuildPointer(priorBuild.CommitSha, priorBuild.VersionString, priorBuild.Latest),
            CurrentScore: Math.Round(currentResult.Score, 1),
            CurrentBand: currentResult.Band,
            PriorScore: priorScore,
            PriorBand: priorBand,
            DeltaPoints: evaluation.DeltaPoints.HasValue ? Math.Round(evaluation.DeltaPoints.Value, 1) : null,
            PolicyId: policy.Id,
            PolicyName: policy.Name,
            Gates: evaluation.Results.Select(g => new GateResultDto(
                g.Key, g.Enabled, g.Passed, g.Observed, g.Threshold, g.Reason)).ToList(),
            GatesEnabled: evaluation.Failed + evaluation.Passed,
            GatesPassed: evaluation.Passed,
            GatesFailed: evaluation.Failed));
    }
}
