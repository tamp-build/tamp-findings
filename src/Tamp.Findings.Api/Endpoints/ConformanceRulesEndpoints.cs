using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Api.Authentication;
using Tamp.Findings.Application.Auditing;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Compliance;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Api.Endpoints;

// TFND-190 / ADR 0012: the authoritative conformance-rules store surfaces. The generation
// step PUSHES a project's rule set here; the analyzer FETCHES the active set to run. Both
// are ingest-token, project-scoped (prj_) — 'self' is unambiguous only for a project token,
// same discipline as the compliance- and zt-profile reads.
public static class ConformanceRulesEndpoints
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public static IEndpointRouteBuilder MapConformanceRules(this IEndpointRouteBuilder app)
    {
        app.MapPost("/projects/self/adr-rules", PushAsync)
           .WithName("PushAdrRules")
           .WithTags("Compliance")
           .WithSummary("Push a conformance-rule generation for the token project (ADR 0012). Whole-set replace: upsert by (adrRef, ruleId), retire dropped rules. Requires a PROJECT-scoped Authorization: Bearer prj_… token.")
           .AllowAnonymous()
           .AddEndpointFilter<IngestAuthFilter>();

        app.MapGet("/projects/self/adr-ruleset", FetchAsync)
           .WithName("FetchAdrRuleset")
           .WithTags("Compliance")
           .WithSummary("The token project's ACTIVE conformance rules — what the analyzer runs. Requires a PROJECT-scoped Authorization: Bearer prj_… token.")
           .AllowAnonymous()
           .AddEndpointFilter<IngestAuthFilter>();
        return app;
    }

    private static async Task<IResult> PushAsync(
        HttpContext ctx, ConformanceRulesService rules, AuditLog audit, FindingsDbContext db, CancellationToken ct)
    {
        var (token, projectId) = SelfProject(ctx);
        if (token is null) return Results.Unauthorized();
        if (projectId is not { } pid) return Results.NotFound("adr-rules not found");

        AdrRuleGeneration? gen;
        try
        {
            gen = await JsonSerializer.DeserializeAsync<AdrRuleGeneration>(ctx.Request.Body, Json, ct);
        }
        catch (JsonException ex) { return Results.BadRequest($"malformed body: {ex.Message}"); }
        if (gen is null) return Results.BadRequest("no generation in body");

        var result = await rules.PushAsync(pid, gen, ct);

        var actorLogin = await db.Users.AsNoTracking()
            .Where(u => u.Id == token.CreatedByUserId).Select(u => u.Login).FirstOrDefaultAsync(ct);
        audit.RecordIngest(token.Id, token.Name, actorLogin is null ? null : token.CreatedByUserId, actorLogin,
            AuditActions.AdrRulesPushed, new ScopeTarget(token.ClientId, pid, null),
            detail: $"adr-rules: {result.Upserted} upserted, {result.Retired} retired, {result.Active} active"
                  + (result.Superseded.Count > 0 ? $", {result.Superseded.Count} mandate POA&M(s) superseded" : ""));
        await db.SaveChangesAsync(ct);

        return Results.Ok(result);
    }

    private static async Task<IResult> FetchAsync(
        HttpContext ctx, ConformanceRulesQuery rules, AuditLog audit, FindingsDbContext db, CancellationToken ct)
    {
        var (token, projectId) = SelfProject(ctx);
        if (token is null) return Results.Unauthorized();
        if (projectId is not { } pid) return Results.NotFound("adr-ruleset not found");

        var ruleset = await rules.ForProjectAsync(pid, ct);

        audit.RecordIngest(token.Id, token.Name, token.CreatedByUserId, null,
            AuditActions.AdrRulesetRead, new ScopeTarget(token.ClientId, pid, null),
            detail: $"adr-ruleset: {ruleset.Rules.Count} active rule(s)");
        await db.SaveChangesAsync(ct);

        return Results.Ok(ruleset);
    }

    private static (IngestToken? Token, Guid? ProjectId) SelfProject(HttpContext ctx)
    {
        var token = IngestAuthFilter.CurrentToken(ctx);
        if (token is null) return (null, null);
        // prj_ only: a client token has no single 'self'.
        return token.Scope == IngestTokenScope.Project ? (token, token.ProjectId) : (token, null);
    }
}
