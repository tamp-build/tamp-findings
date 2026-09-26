using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Poam;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Api.Endpoints;

public sealed record PoamItemDto(
    Guid Id,
    Guid ProjectId,
    string Title,
    string WeaknessDescription,
    string? MitigationPlan,
    string? ResourcesRequired,
    Severity Severity,
    PoamStatus Status,
    DateTimeOffset? ScheduledCompletionDate,
    DateTimeOffset? ActualCompletionDate,
    IReadOnlyList<Guid> LinkedFindingIds,
    string? ReferenceUrl,
    Guid AuthorUserId,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt,
    DateTimeOffset? ClosedAt,
    // Convenience surface for the SPA — true when ScheduledCompletionDate
    // is in the past and Status is still open/in-progress. Same shape the
    // poamPastDue gate uses.
    bool IsPastDue);

public sealed record CreatePoamItemRequest(
    string Title,
    string WeaknessDescription,
    string? MitigationPlan,
    string? ResourcesRequired,
    Severity Severity,
    PoamStatus? Status,
    DateTimeOffset? ScheduledCompletionDate,
    IReadOnlyList<Guid>? LinkedFindingIds,
    string? ReferenceUrl);

public sealed record UpdatePoamItemRequest(
    string? Title,
    string? WeaknessDescription,
    string? MitigationPlan,
    string? ResourcesRequired,
    Severity? Severity,
    PoamStatus? Status,
    DateTimeOffset? ScheduledCompletionDate,
    IReadOnlyList<Guid>? LinkedFindingIds,
    string? ReferenceUrl);

// TFND-156: these writes route through PoamService — the same capability-gated,
// audited path the Blazor UI uses — rather than an Admin-only, unaudited path.
// In particular a status change goes through PoamService.TransitionAsync, so
// moving an item to RiskAccepted needs the InfoSec AcceptRisk capability that
// Admin deliberately does not hold; the old direct-write PATCH bypassed it.
public static class PoamItemEndpoints
{
    public static IEndpointRouteBuilder MapPoamItems(this IEndpointRouteBuilder app)
    {
        var g = app.MapGroup("").WithTags("POA&M");

        g.MapGet("/projects/{projectId:guid}/poam-items", ListAsync)
         .WithSummary("List POA&M items for a project. By default returns live items (ClosedAt is null); pass includeClosed=true to include terminal-status rows.");
        g.MapPost("/projects/{projectId:guid}/poam-items", CreateAsync)
         .WithSummary("Open a new POA&M entry. Requires the CreatePoamItem capability.");

        g.MapPatch("/poam-items/{id:guid}", UpdateAsync)
         .WithSummary("Edit a POA&M entry. Field edits need CreatePoamItem; a status change is applied via TransitionAsync, so RiskAccepted needs AcceptRisk (InfoSec) and Completed needs CompletePoamItem.");
        g.MapDelete("/poam-items/{id:guid}", CloseAsync)
         .WithSummary("Soft-close a POA&M entry (Status=Cancelled + ClosedAt). Row stays for audit; use this when an entry was opened in error. Prefer PATCH with Status=Completed when the weakness was actually remediated.");

        return app;
    }

    private static async Task<IResult> ListAsync(
        Guid projectId, FindingsDbContext db, CancellationToken ct,
        bool includeClosed = false,
        bool pastDueOnly = false,
        PoamStatus? status = null)
    {
        var q = db.PoamItems.AsNoTracking().Where(p => p.ProjectId == projectId);
        if (!includeClosed) q = q.Where(p => p.ClosedAt == null);
        if (status.HasValue) q = q.Where(p => p.Status == status.Value);
        if (pastDueOnly)
        {
            var nowUtc = DateTimeOffset.UtcNow;
            q = q.Where(p =>
                p.ClosedAt == null
                && (p.Status == PoamStatus.Open || p.Status == PoamStatus.InProgress)
                && p.ScheduledCompletionDate != null
                && p.ScheduledCompletionDate < nowUtc);
        }
        // Default sort: open first, then by due date ascending (most
        // overdue surfaces at the top), then by severity descending.
        var rows = await q
            .OrderBy(p => p.ClosedAt != null)
            .ThenBy(p => p.ScheduledCompletionDate ?? DateTimeOffset.MaxValue)
            .ThenByDescending(p => p.Severity)
            .ToListAsync(ct);

        var now = DateTimeOffset.UtcNow;
        var dtos = rows.Select(p => Project(p, now)).ToList();
        return Results.Ok((IReadOnlyList<PoamItemDto>)dtos);
    }

    private static async Task<IResult> CreateAsync(
        Guid projectId, CreatePoamItemRequest req, HttpContext ctx, FindingsDbContext db,
        PrincipalResolver principals, PoamService poam, CancellationToken ct)
    {
        var (actor, scope, deny) = await EndpointActor.ForProjectAsync(ctx, db, principals, projectId, ct);
        if (deny is not null) return deny;

        var draft = new PoamDraft(
            req.Title ?? "",
            req.WeaknessDescription ?? "",
            req.MitigationPlan,
            req.ResourcesRequired,
            req.ReferenceUrl,
            req.Severity,
            req.Status ?? PoamStatus.Open,
            req.ScheduledCompletionDate,
            req.LinkedFindingIds?.ToList() ?? []);

        var result = await poam.CreateAsync(actor!, scope, projectId, draft, ct);
        if (!result.Success) return Fail(result.WasDenied, result.Error);

        var row = await db.PoamItems.AsNoTracking().FirstAsync(p => p.Id == result.Value, ct);
        return Results.Created($"/poam-items/{row.Id}", Project(row, DateTimeOffset.UtcNow));
    }

    private static async Task<IResult> UpdateAsync(
        Guid id, UpdatePoamItemRequest req, HttpContext ctx, FindingsDbContext db,
        PrincipalResolver principals, PoamService poam, CancellationToken ct)
    {
        var item = await db.PoamItems.AsNoTracking().FirstOrDefaultAsync(p => p.Id == id, ct);
        if (item is null) return Results.NotFound();

        var (actor, scope, deny) = await EndpointActor.ForProjectAsync(ctx, db, principals, item.ProjectId, ct);
        if (deny is not null) return deny;

        // Field edits keep the current status; a status change is applied
        // separately via TransitionAsync so the capability matrix decides it.
        var draft = new PoamDraft(
            req.Title ?? item.Title,
            req.WeaknessDescription ?? item.WeaknessDescription,
            req.MitigationPlan ?? item.MitigationPlan,
            req.ResourcesRequired ?? item.ResourcesRequired,
            req.ReferenceUrl ?? item.ReferenceUrl,
            req.Severity ?? item.Severity,
            item.Status,
            req.ScheduledCompletionDate ?? item.ScheduledCompletionDate,
            req.LinkedFindingIds?.ToList() ?? item.LinkedFindingIds);

        var upd = await poam.UpdateAsync(actor!, scope, item.ProjectId, id, draft, ct);
        if (!upd.Success) return Fail(upd.WasDenied, upd.Error);

        if (req.Status.HasValue && req.Status.Value != item.Status)
        {
            var trans = await poam.TransitionAsync(actor!, scope, item.ProjectId, id, req.Status.Value, ct);
            if (!trans.Success) return Fail(trans.WasDenied, trans.Error);
        }

        var row = await db.PoamItems.AsNoTracking().FirstAsync(p => p.Id == id, ct);
        return Results.Ok(Project(row, DateTimeOffset.UtcNow));
    }

    private static async Task<IResult> CloseAsync(
        Guid id, HttpContext ctx, FindingsDbContext db,
        PrincipalResolver principals, PoamService poam, CancellationToken ct)
    {
        var item = await db.PoamItems.AsNoTracking()
            .Select(p => new { p.Id, p.ProjectId, p.ClosedAt })
            .FirstOrDefaultAsync(p => p.Id == id, ct);
        if (item is null) return Results.NotFound();
        if (item.ClosedAt is not null) return Results.NoContent();

        var (actor, scope, deny) = await EndpointActor.ForProjectAsync(ctx, db, principals, item.ProjectId, ct);
        if (deny is not null) return deny;

        var result = await poam.TransitionAsync(actor!, scope, item.ProjectId, id, PoamStatus.Cancelled, ct);
        if (!result.Success) return Fail(result.WasDenied, result.Error);
        return Results.NoContent();
    }

    // A capability denial is a 403 carrying the reason; a validation failure is
    // a 400. (The old path returned a bare 403 with no reason, or 400.)
    private static IResult Fail(bool denied, string? error) =>
        denied ? Results.Problem(error, statusCode: StatusCodes.Status403Forbidden)
               : Results.BadRequest(error);

    private static PoamItemDto Project(PoamItem p, DateTimeOffset nowUtc)
    {
        var live = p.ClosedAt is null && (p.Status == PoamStatus.Open || p.Status == PoamStatus.InProgress);
        var isPastDue = live && p.ScheduledCompletionDate is { } due && due < nowUtc;
        return new PoamItemDto(
            p.Id, p.ProjectId, p.Title, p.WeaknessDescription, p.MitigationPlan,
            p.ResourcesRequired, p.Severity, p.Status, p.ScheduledCompletionDate,
            p.ActualCompletionDate, p.LinkedFindingIds, p.ReferenceUrl,
            p.AuthorUserId, p.CreatedAt, p.UpdatedAt, p.ClosedAt, isPastDue);
    }
}
