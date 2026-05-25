using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Api.Authentication;
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

public static class PoamItemEndpoints
{
    public static IEndpointRouteBuilder MapPoamItems(this IEndpointRouteBuilder app)
    {
        var g = app.MapGroup("").WithTags("POA&M");

        g.MapGet("/projects/{projectId:guid}/poam-items", ListAsync)
         .WithSummary("List POA&M items for a project. By default returns live items (ClosedAt is null); pass includeClosed=true to include terminal-status rows.");
        g.MapPost("/projects/{projectId:guid}/poam-items", CreateAsync)
         .WithSummary("Open a new POA&M entry. Admin only.");

        g.MapPatch("/poam-items/{id:guid}", UpdateAsync)
         .WithSummary("Edit a POA&M entry. Transitioning into Completed / RiskAccepted / Cancelled stamps ClosedAt automatically.");
        g.MapDelete("/poam-items/{id:guid}", CloseAsync)
         .WithSummary("Soft-close a POA&M entry (sets Status=Cancelled + ClosedAt). Row stays for audit; use this when an entry was opened in error. Prefer PATCH with Status=Completed when the weakness was actually remediated.");

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
        Guid projectId, CreatePoamItemRequest req, HttpContext ctx, FindingsDbContext db, CancellationToken ct)
    {
        var (user, deny) = await RequireAdminAsync(ctx, db, ct);
        if (deny is not null) return deny;
        if (string.IsNullOrWhiteSpace(req.Title)) return Results.BadRequest("title required");
        if (string.IsNullOrWhiteSpace(req.WeaknessDescription)) return Results.BadRequest("weaknessDescription required");
        if (!await db.Projects.AnyAsync(p => p.Id == projectId, ct)) return Results.NotFound("project not found");

        var status = req.Status ?? PoamStatus.Open;
        var row = new PoamItem
        {
            ProjectId = projectId,
            Title = req.Title.Trim(),
            WeaknessDescription = req.WeaknessDescription.Trim(),
            MitigationPlan = NullIfBlank(req.MitigationPlan),
            ResourcesRequired = NullIfBlank(req.ResourcesRequired),
            Severity = req.Severity,
            Status = status,
            ScheduledCompletionDate = req.ScheduledCompletionDate,
            LinkedFindingIds = req.LinkedFindingIds?.ToList() ?? new List<Guid>(),
            ReferenceUrl = NullIfBlank(req.ReferenceUrl),
            AuthorUserId = user!.Id,
            ClosedAt = IsTerminal(status) ? DateTimeOffset.UtcNow : null,
            ActualCompletionDate = status == PoamStatus.Completed ? DateTimeOffset.UtcNow : null,
        };
        db.PoamItems.Add(row);
        await db.SaveChangesAsync(ct);
        return Results.Created($"/poam-items/{row.Id}", Project(row, DateTimeOffset.UtcNow));
    }

    private static async Task<IResult> UpdateAsync(
        Guid id, UpdatePoamItemRequest req, HttpContext ctx, FindingsDbContext db, CancellationToken ct)
    {
        var (_, deny) = await RequireAdminAsync(ctx, db, ct);
        if (deny is not null) return deny;
        var row = await db.PoamItems.FirstOrDefaultAsync(p => p.Id == id, ct);
        if (row is null) return Results.NotFound();

        if (req.Title is not null) row.Title = req.Title.Trim();
        if (req.WeaknessDescription is not null) row.WeaknessDescription = req.WeaknessDescription.Trim();
        if (req.MitigationPlan is not null) row.MitigationPlan = NullIfBlank(req.MitigationPlan);
        if (req.ResourcesRequired is not null) row.ResourcesRequired = NullIfBlank(req.ResourcesRequired);
        if (req.Severity.HasValue) row.Severity = req.Severity.Value;
        if (req.ScheduledCompletionDate.HasValue) row.ScheduledCompletionDate = req.ScheduledCompletionDate;
        if (req.LinkedFindingIds is not null) row.LinkedFindingIds = req.LinkedFindingIds.ToList();
        if (req.ReferenceUrl is not null) row.ReferenceUrl = NullIfBlank(req.ReferenceUrl);

        if (req.Status.HasValue && req.Status.Value != row.Status)
        {
            var newStatus = req.Status.Value;
            row.Status = newStatus;
            // Terminal status stamps ClosedAt; transitioning OUT of a
            // terminal status (rare — usually a correction) clears it.
            if (IsTerminal(newStatus))
            {
                row.ClosedAt ??= DateTimeOffset.UtcNow;
                if (newStatus == PoamStatus.Completed)
                    row.ActualCompletionDate ??= DateTimeOffset.UtcNow;
            }
            else
            {
                row.ClosedAt = null;
                row.ActualCompletionDate = null;
            }
        }

        row.UpdatedAt = DateTimeOffset.UtcNow;
        await db.SaveChangesAsync(ct);
        return Results.Ok(Project(row, DateTimeOffset.UtcNow));
    }

    private static async Task<IResult> CloseAsync(
        Guid id, HttpContext ctx, FindingsDbContext db, CancellationToken ct)
    {
        var (_, deny) = await RequireAdminAsync(ctx, db, ct);
        if (deny is not null) return deny;
        var row = await db.PoamItems.FirstOrDefaultAsync(p => p.Id == id, ct);
        if (row is null) return Results.NotFound();
        if (row.ClosedAt is not null) return Results.NoContent();
        row.Status = PoamStatus.Cancelled;
        row.ClosedAt = DateTimeOffset.UtcNow;
        row.UpdatedAt = DateTimeOffset.UtcNow;
        await db.SaveChangesAsync(ct);
        return Results.NoContent();
    }

    private static bool IsTerminal(PoamStatus s) =>
        s == PoamStatus.Completed || s == PoamStatus.RiskAccepted || s == PoamStatus.Cancelled;

    private static string? NullIfBlank(string? s) =>
        string.IsNullOrWhiteSpace(s) ? null : s.Trim();

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

    private static async Task<(User? user, IResult? deny)> RequireAdminAsync(HttpContext ctx, FindingsDbContext db, CancellationToken ct)
    {
        if (!Guid.TryParse(ctx.User.FindFirstValue(AuthExtensions.TampUserIdClaim), out var uid))
            return (null, Results.Unauthorized());
        var user = await db.Users.FirstOrDefaultAsync(u => u.Id == uid, ct);
        if (user is null || !user.IsApproved) return (null, Results.Unauthorized());
        if (!user.IsAdmin) return (user, Results.Forbid());
        return (user, null);
    }
}
