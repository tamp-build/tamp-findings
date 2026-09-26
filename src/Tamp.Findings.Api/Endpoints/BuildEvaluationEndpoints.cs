using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Api.Services;
using Tamp.Findings.Application.Risk;
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
    int GatesBlocking,
    // The effective enforcement mode for this project (ADR 0004): "Advisory"
    // or "Enforcing", after Project -> Client -> Instance resolution and the
    // config lock. The CLI gate reads this to decide whether a blocking verdict
    // fails the build; the dashboard reads it to say whether it would.
    string EnforcementMode);

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
        GateDecisionService decisions,
        CancellationToken ct)
    {
        // Canonical resolution + evaluation + enforcement mode live in
        // GateDecisionService, shared with the bearer-authed CLI gate endpoint
        // so the two surfaces cannot drift.
        var (status, r) = await decisions.ForLatestAsync(projectId, ct);
        return status switch
        {
            GateDecisionStatus.ProjectNotFound => Results.NotFound("project not found"),
            GateDecisionStatus.NoBuilds => Results.NotFound("no canonical builds for this project"),
            GateDecisionStatus.NoPolicy => Results.Conflict("no default risk policy seeded"),
            _ => Results.Ok(new BuildEvaluationResponse(
                Current: new BuildPointer(r!.Current.CommitSha, r.Current.VersionString, r.Current.LatestCreatedAt),
                Prior: r.Prior is null ? null : new BuildPointer(r.Prior.CommitSha, r.Prior.VersionString, r.Prior.LatestCreatedAt),
                CurrentScore: r.CurrentScore,
                CurrentBand: r.CurrentBand,
                PriorScore: r.PriorScore,
                PriorBand: r.PriorBand,
                DeltaPoints: r.Evaluation.DeltaPoints.HasValue ? Math.Round(r.Evaluation.DeltaPoints.Value, 1) : null,
                PolicyId: r.PolicyId,
                PolicyName: r.PolicyName,
                Gates: r.Evaluation.Results.Select(g => new GateResultDto(
                    g.Key, g.Enabled, g.Verdict.ToString(), g.Blocks, g.Observed, g.Threshold, g.Reason)).ToList(),
                // Read straight off the evaluation. Reconstructing this as
                // Passed + Failed is what produced the "9 gates enabled" line
                // that contradicted a computed 10, and it silently drops
                // Unknown and Error.
                GatesEnabled: r.Evaluation.Enabled,
                GatesPassed: r.Evaluation.Passed,
                GatesFailed: r.Evaluation.Failed,
                GatesUnknown: r.Evaluation.Unknown,
                GatesBlocking: r.Evaluation.Blocking,
                EnforcementMode: r.Mode.ToString())),
        };
    }
}
