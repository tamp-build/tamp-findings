using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Application.Poam;

/// <summary>
/// The POA&amp;M read model (TFND-95 / TFND-96).
///
/// POA&amp;M is the federal record — NIST SP 800-53 CA-5 — that a weakness
/// exists, who owns it, and when it closes. An Authorizing Official reviews it
/// monthly, which is why the screen leads with the counts and the past-due
/// gate rather than with a list.
/// </summary>
public sealed class PoamQuery
{
    private readonly FindingsDbContext _db;

    public PoamQuery(FindingsDbContext db) => _db = db;

    /// <summary>
    /// Every item on the project, with the stats strip already computed.
    ///
    /// <paramref name="asOf"/> is passed rather than read from the clock so the
    /// caller pins ONE instant. Reading UtcNow per row would let an item be
    /// past due in the stats strip and not in the table on the same page —
    /// which is exactly the kind of internal disagreement that makes a reader
    /// stop trusting a compliance screen.
    /// </summary>
    public async Task<PoamBoard> BoardAsync(Guid projectId, DateTimeOffset asOf, CancellationToken ct = default)
    {
        var items = await _db.PoamItems.AsNoTracking()
            .Where(p => p.ProjectId == projectId)
            .Select(p => new
            {
                p.Id, p.Title, p.Severity, p.Status, p.ScheduledCompletionDate,
                p.CreatedAt, p.ClosedAt, p.WeaknessDescription, p.LinkedFindingIds, p.AuthorUserId,
            })
            .ToArrayAsync(ct);

        var authorIds = items.Select(i => i.AuthorUserId).Distinct().ToArray();
        var authors = await _db.Users.AsNoTracking()
            .Where(u => authorIds.Contains(u.Id))
            .Select(u => new { u.Id, u.DisplayName })
            .ToArrayAsync(ct);
        var authorNames = authors.ToDictionary(a => a.Id, a => a.DisplayName);

        var rows = items
            .Select(p => new PoamRow(
                p.Id,
                p.Title,
                p.WeaknessDescription,
                p.Severity,
                p.Status,
                authorNames.TryGetValue(p.AuthorUserId, out var name) ? name : "(unknown)",
                p.ScheduledCompletionDate,
                p.CreatedAt,
                p.ClosedAt,
                IsPastDue(p.Status, p.ClosedAt, p.ScheduledCompletionDate, asOf),
                p.LinkedFindingIds.Count))
            // Past due first, then by severity, then by due date. An AO opening
            // this page is asking "what has slipped", and that has to be the
            // first thing on the screen.
            .OrderByDescending(r => r.PastDue)
            .ThenByDescending(r => r.Severity)
            .ThenBy(r => r.ScheduledCompletionDate ?? DateTimeOffset.MaxValue)
            .ThenBy(r => r.Title, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        return new PoamBoard(
            rows,
            new PoamStats(
                Open: rows.Count(r => r.Status == PoamStatus.Open),
                InProgress: rows.Count(r => r.Status == PoamStatus.InProgress),
                Completed: rows.Count(r => r.Status == PoamStatus.Completed),
                RiskAccepted: rows.Count(r => r.Status == PoamStatus.RiskAccepted),
                Cancelled: rows.Count(r => r.Status == PoamStatus.Cancelled),
                PastDue: rows.Count(r => r.PastDue),
                Unscheduled: rows.Count(r => r.ScheduledCompletionDate is null && r.ClosedAt is null)));
    }

    /// <summary>The full federal-template record, with its linked findings resolved.</summary>
    public async Task<PoamRecord?> RecordAsync(
        Guid projectId, Guid itemId, DateTimeOffset asOf, CancellationToken ct = default)
    {
        var item = await _db.PoamItems.AsNoTracking()
            .SingleOrDefaultAsync(p => p.Id == itemId && p.ProjectId == projectId, ct);
        if (item is null) return null;

        var author = await _db.Users.AsNoTracking()
            .Where(u => u.Id == item.AuthorUserId)
            .Select(u => u.DisplayName)
            .SingleOrDefaultAsync(ct);

        // Linked findings are resolved against the PROJECT, not globally: an id
        // that belongs to someone else's project must not render here even if
        // it is somehow stored on the item.
        var links = await (
            from f in _db.Findings.AsNoTracking()
            join cv in _db.ComponentVersions.AsNoTracking() on f.ComponentVersionId equals cv.Id
            join c in _db.Components.AsNoTracking() on cv.ComponentId equals c.Id
            where c.ProjectId == projectId && item.LinkedFindingIds.Contains(f.Id)
            select new PoamLink(f.Id, f.Severity, f.RuleId, f.Title, f.FilePath, f.Scanner, cv.CommitSha))
            .ToArrayAsync(ct);

        // Ids the item claims that no longer resolve. Silently dropping them
        // would let a POA&M cite evidence that has since been deleted and still
        // look complete to an auditor.
        var danglingCount = item.LinkedFindingIds.Distinct().Count() - links.Length;

        return new PoamRecord(
            item.Id,
            item.Title,
            item.WeaknessDescription,
            item.MitigationPlan,
            item.ResourcesRequired,
            item.Severity,
            item.Status,
            author ?? "(unknown)",
            item.ScheduledCompletionDate,
            item.ActualCompletionDate,
            item.ReferenceUrl,
            item.CreatedAt,
            item.UpdatedAt,
            item.ClosedAt,
            IsPastDue(item.Status, item.ClosedAt, item.ScheduledCompletionDate, asOf),
            links,
            danglingCount);
    }

    /// <summary>
    /// Past due exactly as <c>RiskInputsBuilder</c> counts it for the
    /// <c>poamPastDue</c> gate: still live, actually scheduled, and the date
    /// has passed.
    ///
    /// An UNSCHEDULED item is never past due — it has no date to be past. That
    /// is a real hole in the gate, but it is the gate's hole, and the screen
    /// showing a different number than the gate would be worse. The stats strip
    /// surfaces the unscheduled count separately so the hole is visible rather
    /// than hidden.
    /// </summary>
    public static bool IsPastDue(
        PoamStatus status, DateTimeOffset? closedAt, DateTimeOffset? scheduled, DateTimeOffset asOf) =>
        closedAt is null
        && status is PoamStatus.Open or PoamStatus.InProgress
        && scheduled is { } due
        && due < asOf;
}

public sealed record PoamBoard(IReadOnlyList<PoamRow> Items, PoamStats Stats);

public sealed record PoamStats(
    int Open, int InProgress, int Completed, int RiskAccepted, int Cancelled,
    int PastDue, int Unscheduled);

public sealed record PoamRow(
    Guid Id,
    string Title,
    string WeaknessDescription,
    Severity Severity,
    PoamStatus Status,
    string Owner,
    DateTimeOffset? ScheduledCompletionDate,
    DateTimeOffset CreatedAt,
    DateTimeOffset? ClosedAt,
    bool PastDue,
    int LinkCount);

public sealed record PoamRecord(
    Guid Id,
    string Title,
    string WeaknessDescription,
    string? MitigationPlan,
    string? ResourcesRequired,
    Severity Severity,
    PoamStatus Status,
    string Owner,
    DateTimeOffset? ScheduledCompletionDate,
    DateTimeOffset? ActualCompletionDate,
    string? ReferenceUrl,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt,
    DateTimeOffset? ClosedAt,
    bool PastDue,
    IReadOnlyList<PoamLink> LinkedFindings,
    int UnresolvedLinkCount);

public sealed record PoamLink(
    Guid FindingId, Severity Severity, string RuleId, string Title,
    string? FilePath, ScannerKind Scanner, string? CommitSha);
