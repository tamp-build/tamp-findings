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
    int GatesFailed,
    // Gates that could not be evaluated at all — the scanner did not run.
    // A build with unknowns is not a clean build.
    int GatesUnknown,
    // Everything that is not a Pass. This is the number the ship verdict
    // reads; GatesFailed alone would let an unscanned build look clear.
    int GatesBlocking);

public sealed record BuildPointer(
    string? CommitSha,
    string VersionString,
    DateTimeOffset LatestCreatedAt);

public sealed record GateResultDto(
    string Key, bool Enabled,
    // "Pass" | "Fail" | "Unknown" | "Error" (ADR 0001). Unknown means the
    // gate could not be evaluated — typically the scanner never ran — and
    // blocks the release just as Fail does, but with a different remedy.
    string Verdict,
    // True for everything except Pass. The release decision, so a client
    // does not have to know which verdicts block.
    bool Blocks,
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

        var currentInputs = await inputsBuilder.BuildAsync(currentBuild.CvIds, policy.Config, projectId, ct);
        var currentResult = RiskScorer.Compute(policy.Config, currentInputs);

        RiskInputs? priorInputs = null;
        double? priorScore = null;
        string? priorBand = null;
        if (priorBuild is not null)
        {
            priorInputs = await inputsBuilder.BuildAsync(priorBuild.CvIds, policy.Config, projectId, ct);
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
                g.Key, g.Enabled, g.Verdict.ToString(), g.Blocks, g.Observed, g.Threshold, g.Reason)).ToList(),
            // Read straight off the evaluation. Reconstructing this as
            // Passed + Failed is what produced the "9 gates enabled" line
            // that contradicted a computed 10, and it silently drops
            // Unknown and Error.
            GatesEnabled: evaluation.Enabled,
            GatesPassed: evaluation.Passed,
            GatesFailed: evaluation.Failed,
            GatesUnknown: evaluation.Unknown,
            GatesBlocking: evaluation.Blocking));
    }
}
