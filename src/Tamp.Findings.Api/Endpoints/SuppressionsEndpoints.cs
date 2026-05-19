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
           .WithSummary("Create a suppression. Requires X-Author-User and X-Author-Role headers (POC auth).");

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
        CancellationToken ct)
    {
        // POC auth — header-based. Real OIDC plumbing lands in F3.3.
        var userLogin = http.Request.Headers["X-Author-User"].ToString();
        var roleStr = http.Request.Headers["X-Author-Role"].ToString();

        if (string.IsNullOrWhiteSpace(userLogin)) return TypedResults.BadRequest("X-Author-User header is required");
        if (string.IsNullOrWhiteSpace(roleStr)) return TypedResults.BadRequest("X-Author-Role header is required");

        if (!Enum.TryParse<ProjectRole>(roleStr, ignoreCase: true, out var role))
        {
            return TypedResults.BadRequest($"X-Author-Role must be one of: InfoSecOfficer, LeadDev, Architect (was '{roleStr}')");
        }

        // Validate scope-specific fields.
        var validation = ValidateScope(req);
        if (validation is not null) return TypedResults.BadRequest(validation);
        if (string.IsNullOrWhiteSpace(req.Reason)) return TypedResults.BadRequest("reason is required");

        // Find-or-create the user. In POC mode the named roles are gated
        // by header trust; once OIDC lands we'll resolve the user from
        // the verified subject claim instead.
        var user = await db.Users.FirstOrDefaultAsync(u => u.Login == userLogin, ct);
        if (user is null)
        {
            user = new User
            {
                Login = userLogin,
                DisplayName = userLogin,
            };
            db.Users.Add(user);
            await db.SaveChangesAsync(ct);
        }

        var s = new Suppression
        {
            Scope = req.Scope,
            FindingId = req.FindingId,
            RuleId = req.RuleId,
            ComponentId = req.ComponentId,
            FilePath = req.FilePath,
            CreatedByUserId = user.Id,
            CreatedByRole = role,
            Reason = req.Reason,
            ExpiresAt = req.ExpiresAt,
        };
        db.Suppressions.Add(s);
        await db.SaveChangesAsync(ct);

        return TypedResults.Ok(ToResponse(s, user.Login));
    }

    private static async Task<Ok<IReadOnlyList<SuppressionResponse>>> ListAsync(
        FindingsDbContext db,
        CancellationToken ct,
        bool activeOnly = true,
        Guid? componentId = null,
        string? ruleId = null)
    {
        var now = DateTimeOffset.UtcNow;
        var q = db.Suppressions.AsNoTracking();
        if (activeOnly) q = q.Where(s => s.ExpiresAt == null || s.ExpiresAt > now);
        if (componentId is { } cid) q = q.Where(s => s.ComponentId == cid);
        if (!string.IsNullOrWhiteSpace(ruleId)) q = q.Where(s => s.RuleId == ruleId);

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
        _ => null,
    };

    private static SuppressionResponse ToResponse(Suppression s, string login) => new(
        s.Id, s.Scope, s.FindingId, s.RuleId, s.ComponentId, s.FilePath,
        s.CreatedByUserId, login, s.CreatedByRole,
        s.Reason, s.ExpiresAt, s.CreatedAt,
        IsActive: s.ExpiresAt is null || s.ExpiresAt > DateTimeOffset.UtcNow);
}
