using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Application.Auditing;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Application.Poam;

/// <summary>
/// POA&amp;M due-date reminders (TFND-121).
///
/// Was an Elsa Timer workflow; now a plain scheduled sweep driven by a hosted
/// worker (ADR 0005 — Elsa removed). A reminder is a thing that must happen on
/// a schedule whether or not anyone opens the app; that is a background job, not
/// workflow orchestration, and the repo already runs several such sweeps.
///
/// It reminds on items due SOON, not on items already past due — those are
/// already failing the poamPastDue gate and sitting at the top of the table in
/// red, so another notification adds nothing and teaches people to mute these.
/// The window is the last week before the committed date, when doing something
/// about it is still possible.
/// </summary>
public sealed class PoamReminderService
{
    // A week is long enough to act and short enough that the reminder is about
    // this week's work.
    private static readonly TimeSpan Window = TimeSpan.FromDays(7);

    private readonly FindingsDbContext _db;
    private readonly AuditLog _audit;

    public PoamReminderService(FindingsDbContext db, AuditLog audit)
    {
        _db = db;
        _audit = audit;
    }

    /// <summary>Record a reminder for every live POA&amp;M due within the window.</summary>
    public async Task<int> SweepAsync(DateTimeOffset asOf, CancellationToken ct = default)
    {
        var cutoff = asOf + Window;

        // One instant for the whole sweep, so an item cannot fall in and out of
        // the window between two rows of the same run.
        var due = await _db.PoamItems.AsNoTracking()
            .Where(p => p.ClosedAt == null
                     && (p.Status == PoamStatus.Open || p.Status == PoamStatus.InProgress)
                     && p.ScheduledCompletionDate != null
                     && p.ScheduledCompletionDate <= cutoff
                     && p.ScheduledCompletionDate > asOf)
            .Select(p => new { p.Id, p.ProjectId, p.Title, Due = p.ScheduledCompletionDate!.Value })
            .ToListAsync(ct);

        if (due.Count == 0) return 0;

        foreach (var item in due)
        {
            _audit.RecordSystem("poam.due_soon", AuditClass.Risk,
                new ScopeTarget(null, item.ProjectId),
                subjectId: item.Id, subjectKind: "PoamItem",
                detail: $"\"{item.Title}\" is due {item.Due:yyyy-MM-dd} "
                      + $"({(item.Due - asOf).TotalDays:0} days). Close it, get an AO extension, "
                      + "or move it to risk-accepted.");
        }

        await _db.SaveChangesAsync(ct);
        return due.Count;
    }
}
