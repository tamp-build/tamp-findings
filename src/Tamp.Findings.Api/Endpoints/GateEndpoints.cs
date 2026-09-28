using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Api.Authentication;
using Tamp.Findings.Application.Risk;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Api.Endpoints;

// TFND-150: the bearer-gated gate decision the CLI reads. The same cli_/prj_
// ingest token that posted the build reads its verdict here — build-evaluation
// is cookie-authed and unusable from CI. Scoped to the token's project/client.
public sealed record CliGateResponse(
    Guid ProjectId,
    string? CommitSha,
    string VersionString,
    // "Advisory" | "Enforcing" — the effective mode after Project -> Client ->
    // Instance resolution and the deployment config lock.
    string EnforcementMode,
    int GatesEnabled,
    int GatesBlocking,
    int GatesFailed,
    int GatesUnknown,
    // N/A gates ship but are not "passing" — a conditional gate (DAST, IaC,
    // base-image age) the build's components cannot produce (TFND-184). Surfaced
    // so the CLI summary does not silently fold them into the passing count.
    int GatesNotApplicable,
    IReadOnlyList<CliGateVerdict> Gates);

public sealed record CliGateVerdict(
    string Key, string Verdict, bool Blocks, string Observed, string? Reason);

public static class GateEndpoints
{
    public static IEndpointRouteBuilder MapGate(this IEndpointRouteBuilder app)
    {
        app.MapGet("/projects/{projectId:guid}/gate", GateAsync)
           .WithName("GateDecision")
           .WithTags("Gate")
           .WithSummary("Gate verdict + effective enforcement mode for the latest canonical build of a project, for the CLI gate. Requires Authorization: Bearer cli_… or prj_… scoped to the project.")
           .AllowAnonymous()
           .AddEndpointFilter<IngestAuthFilter>();
        return app;
    }

    private static async Task<IResult> GateAsync(
        Guid projectId,
        HttpContext ctx,
        FindingsDbContext db,
        GateDecisionService decisions,
        CancellationToken ct)
    {
        var token = IngestAuthFilter.CurrentToken(ctx);
        if (token is null) return Results.Unauthorized();

        // Scope the token to this project: a prj_ token must match it exactly, a
        // cli_ token must own its client. Out of scope reads as not-found, never
        // a confirmation that another tenant's project exists.
        var proj = await db.Projects.AsNoTracking()
            .Where(p => p.Id == projectId)
            .Select(p => new { p.Id, p.ClientId })
            .FirstOrDefaultAsync(ct);
        if (proj is null) return Results.NotFound("project not found");

        var inScope = token.Scope == IngestTokenScope.Project
            ? token.ProjectId == projectId
            : token.ClientId == proj.ClientId;
        if (!inScope) return Results.NotFound("project not found");

        var (status, r) = await decisions.ForLatestAsync(projectId, ct);
        return status switch
        {
            GateDecisionStatus.ProjectNotFound => Results.NotFound("project not found"),
            GateDecisionStatus.NoBuilds => Results.NotFound("no canonical builds for this project"),
            GateDecisionStatus.NoPolicy => Results.Conflict("no default risk policy seeded"),
            _ => Results.Ok(new CliGateResponse(
                ProjectId: projectId,
                CommitSha: r!.Current.CommitSha,
                VersionString: r.Current.VersionString,
                EnforcementMode: r.Mode.ToString(),
                GatesEnabled: r.Evaluation.Enabled,
                GatesBlocking: r.Evaluation.Blocking,
                GatesFailed: r.Evaluation.Failed,
                GatesUnknown: r.Evaluation.Unknown,
                GatesNotApplicable: r.Evaluation.NotApplicable,
                Gates: r.Evaluation.Results.Where(g => g.Enabled).Select(g => new CliGateVerdict(
                    g.Key, g.Verdict.ToString(), g.Blocks, g.Observed, g.Reason)).ToList())),
        };
    }
}
