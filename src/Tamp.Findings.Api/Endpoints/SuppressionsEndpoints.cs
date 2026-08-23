using Tamp.Findings.Application.Auditing;
using Tamp.Findings.Api.Authentication;
using Tamp.Findings.Application.Authorization;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Api.Contracts;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Api.Endpoints;

public static class SuppressionsEndpoints
{
    public static IEndpointRouteBuilder MapSuppressions(this IEndpointRouteBuilder app)
    {
        app.MapPost("/suppressions", CreateAsync)
           .WithName("CreateSuppression")
           .WithSummary("Create a suppression. Requires an authenticated session and the AuthorSuppression capability at the target scope.");

        app.MapGet("/suppressions", ListAsync)
           .WithName("ListSuppressions")
           .WithSummary("List suppressions, optionally filtered to active-only");

        app.MapDelete("/suppressions/{id:guid}", DeleteAsync)
           .WithName("DeleteSuppression")
           .WithSummary("Remove a suppression");

        return app;
    }

    private static async Task<Results<Ok<SuppressionResponse>, BadRequest<string>, ForbidHttpResult>> CreateAsync(
        SuppressionCreateRequest req,
        HttpContext http,
        FindingsDbContext db,
        CapabilityEvaluator capabilities,
        PrincipalResolver principals,
        AuditLog audit,
        ILoggerFactory logs,
        CancellationToken ct)
    {
        // Who is acting comes from the AUTHENTICATED COOKIE, never from a
        // header. X-Author-Role used to be parsed and trusted here: anyone who
        // could reach the endpoint could claim any role by typing it, which
        // ADR 0001 flagged and TFND-19 tracked. That is what this replaces.
        //
        // The legacy header path survives ONLY behind an explicit env var for
        // the POC ingest tests, and is refused whenever authentication is
        // actually configured — see SuppressionAuthorization.
        var acting = await SuppressionAuthorization.ResolveActorAsync(http, principals, db, req, ct);
        if (acting.Error is not null) return TypedResults.BadRequest(acting.Error);
        if (acting.Principal is null || acting.User is null) return TypedResults.Forbid();

        var decision = capabilities.Evaluate(acting.Principal, Capability.AuthorSuppression);
        if (!decision.Allowed)
        {
            // ForbidHttpResult carries no body, so the reason goes to the log
            // rather than being lost — a 403 nobody can explain is a support
            // ticket. The Blazor UI reads the evaluator directly and shows the
            // reason inline instead (ADR 0002).
            logs.CreateLogger("Tamp.Findings.Suppressions")
                .LogWarning("Suppression denied for {Login} at {Target}: {Reason}",
                    acting.User.Login, acting.Target, decision.Reason);
            return TypedResults.Forbid();
        }

        // Validate scope-specific fields.
        var validation = ValidateScope(req);
        if (validation is not null) return TypedResults.BadRequest(validation);
        if (string.IsNullOrWhiteSpace(req.Reason)) return TypedResults.BadRequest("reason is required");

        var user = acting.User;
        var role = acting.RecordedRole;

        var s = new Suppression
        {
            Scope = req.Scope,
            FindingId = req.FindingId,
            RuleId = req.RuleId,
            ComponentId = req.ComponentId,
            FilePath = req.FilePath,
            // From the RESOLVED target, not from the request (TFND-132). The
            // target is what the capability check ran against, so binding the
            // row to it means a suppression can never reach further than the
            // authorization that permitted it.
            ClientId = acting.Target.ClientId,
            ProjectId = acting.Target.ProjectId,
            CreatedByUserId = user.Id,
            CreatedByRole = role,
            Reason = req.Reason,
            ExpiresAt = req.ExpiresAt,
        };
        db.Suppressions.Add(s);

        // Same transaction as the suppression itself. An audit entry that can
        // survive a rolled-back action, or an action that can commit without
        // one, would both make the trail a description of what was attempted
        // rather than what happened.
        audit.Record(
            acting.Principal,
            AuditActions.SuppressionAuthored,
            AuditClass.Risk,
            acting.Target,
            subjectId: s.Id,
            subjectKind: nameof(Suppression),
            detail: $"{req.Scope} suppression: {req.Reason}");

        await db.SaveChangesAsync(ct);

        return TypedResults.Ok(ToResponse(s, user.Login));
    }

    private static async Task<Ok<IReadOnlyList<SuppressionResponse>>> ListAsync(
        FindingsDbContext db,
        CancellationToken ct,
        bool activeOnly = true,
        Guid? componentId = null,
        string? ruleId = null,
        Guid? projectId = null)
    {
        var now = DateTimeOffset.UtcNow;
        var q = db.Suppressions.AsNoTracking();
        if (activeOnly) q = q.Where(s => s.ExpiresAt == null || s.ExpiresAt > now);
        if (componentId is { } cid) q = q.Where(s => s.ComponentId == cid);
        if (!string.IsNullOrWhiteSpace(ruleId)) q = q.Where(s => s.RuleId == ruleId);

        // TFND-132: everything that can silence a finding in this project —
        // its own rows, its client's, and the legacy instance-wide ones that
        // still apply. Filtering to `ProjectId == pid` alone would hide exactly
        // the rows that used to be invisible, which is the defect.
        if (projectId is { } pid)
        {
            q = q.Where(s => s.ProjectId == pid || (s.ProjectId == null && s.ClientId == null)
                             || (s.ProjectId == null && s.ClientId != null
                                 && db.Projects.Any(p => p.Id == pid && p.ClientId == s.ClientId)));
        }

        // Join to user for the response — manual because we don't have a
        // navigation on Suppression (intentionally — keeps the entity flat).
        var rows = await (
            from s in q
            join u in db.Users.AsNoTracking() on s.CreatedByUserId equals u.Id into us
            from u in us.DefaultIfEmpty()
            orderby s.CreatedAt descending
            select new { s, u }
        ).ToListAsync(ct);

        var items = (IReadOnlyList<SuppressionResponse>)rows
            .Select(row => ToResponse(row.s, row.u?.Login ?? "(unknown)"))
            .ToList();
        return TypedResults.Ok(items);
    }

    private static async Task<Results<NoContent, NotFound>> DeleteAsync(Guid id, FindingsDbContext db, CancellationToken ct)
    {
        var s = await db.Suppressions.FindAsync([id], ct);
        if (s is null) return TypedResults.NotFound();
        db.Suppressions.Remove(s);
        await db.SaveChangesAsync(ct);
        return TypedResults.NoContent();
    }

    private static string? ValidateScope(SuppressionCreateRequest req) => req.Scope switch
    {
        SuppressionScope.SingleFinding when req.FindingId is null => "SingleFinding scope requires findingId",
        SuppressionScope.RuleOnFile when string.IsNullOrWhiteSpace(req.RuleId) => "RuleOnFile scope requires ruleId",
        SuppressionScope.RuleOnFile when string.IsNullOrWhiteSpace(req.FilePath) => "RuleOnFile scope requires filePath",
        SuppressionScope.RuleOnComponent when string.IsNullOrWhiteSpace(req.RuleId) => "RuleOnComponent scope requires ruleId",
        SuppressionScope.RuleOnComponent when req.ComponentId is null => "RuleOnComponent scope requires componentId",
        SuppressionScope.RuleEverywhere when string.IsNullOrWhiteSpace(req.RuleId) => "RuleEverywhere scope requires ruleId",

        // TFND-132. The rule-scoped kinds carry no anchor of their own, so the
        // project is the only thing bounding them. Refusing here rather than
        // defaulting to instance-wide: a suppression whose blast radius was
        // never stated should not silently get the largest one.
        SuppressionScope.RuleOnFile when req.ProjectId is null =>
            "RuleOnFile scope requires projectId — without it the rule would be silenced for every client",
        SuppressionScope.RuleEverywhere when req.ProjectId is null =>
            "RuleEverywhere scope requires projectId — without it the rule would be silenced for every client",

        _ => null,
    };

    private static SuppressionResponse ToResponse(Suppression s, string login) => new(
        s.Id, s.Scope, s.FindingId, s.RuleId, s.ComponentId, s.FilePath,
        s.CreatedByUserId, login, s.CreatedByRole,
        s.Reason, s.ExpiresAt, s.CreatedAt,
        IsActive: s.ExpiresAt is null || s.ExpiresAt > DateTimeOffset.UtcNow);
}
