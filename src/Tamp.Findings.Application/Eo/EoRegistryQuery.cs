using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Compliance;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Application.Eo;

// Read side of the EO registry (ADR 0011 §7). The point-in-time engine: what was
// mandated, by what authority, and in force, as of any date. Pure status math lives in
// DirectiveStatusResolver; this assembles the rows and joins the crosswalk.
public sealed class EoRegistryQuery(FindingsDbContext db)
{
    /// <summary>
    /// The registry as of <paramref name="asOf"/> (defaults to now): every reviewed
    /// directive with its status on that date, its resolved deadline, and its crosswalk.
    /// A compliance claim is only meaningful against the set in force *then*.
    /// </summary>
    public async Task<IReadOnlyList<EoDirectiveView>> AsOfAsync(
        DateTimeOffset? asOf = null, CancellationToken ct = default)
    {
        var when = asOf ?? DateTimeOffset.UtcNow;

        var directives = await db.Directives.AsNoTracking().ToListAsync(ct);
        var instruments = (await db.Instruments.AsNoTracking().ToListAsync(ct))
            .ToDictionary(i => i.Id);
        var changes = (await db.DirectiveStatusChanges.AsNoTracking().ToListAsync(ct))
            .GroupBy(s => s.DirectiveId).ToDictionary(g => g.Key, g => g.ToList());
        var crosswalks = (await db.DirectiveCrosswalks.AsNoTracking().ToListAsync(ct))
            .GroupBy(c => c.DirectiveId).ToDictionary(g => g.Key, g => g.First());

        var views = new List<EoDirectiveView>();
        foreach (var d in directives)
        {
            var directiveChanges = changes.GetValueOrDefault(d.Id) ?? [];
            var status = DirectiveStatusResolver.StatusAsOf(directiveChanges, when);
            if (status is null) continue; // did not yet exist as of this date

            instruments.TryGetValue(d.InstrumentId, out var inst);
            crosswalks.TryGetValue(d.Id, out var cx);

            views.Add(new EoDirectiveView(
                d.Ref, inst?.Identifier ?? "?", inst?.Title,
                d.Who, d.MustDo, d.Type, d.Applicability,
                status.Value, d.ByWhenKind, d.ResolvedDate,
                cx?.Target, cx?.TargetRef));
        }

        return views
            .OrderBy(v => v.InstrumentIdentifier, StringComparer.Ordinal)
            .ThenBy(v => v.Ref, StringComparer.Ordinal)
            .ToList();
    }

    /// <summary>The in-force (Active) subset as of a date — the mandate set a system is
    /// actually evaluated against then.</summary>
    public async Task<IReadOnlyList<EoDirectiveView>> InForceAsOfAsync(
        DateTimeOffset? asOf = null, CancellationToken ct = default)
        => (await AsOfAsync(asOf, ct)).Where(v => v.Status == DirectiveStatus.Active).ToList();

    /// <summary>Delegations whose deadline is still unresolved (Pending) — an EO handed a
    /// deadline to a memo that has not issued yet. Surfaced so it is visibly tracked
    /// rather than lost (ADR 0011 open item #3).</summary>
    public async Task<IReadOnlyList<EoDirectiveView>> PendingAsync(CancellationToken ct = default)
        => (await AsOfAsync(DateTimeOffset.UtcNow, ct))
            .Where(v => v.ByWhenKind == ByWhenKind.Pending).ToList();
}

public sealed record EoDirectiveView(
    string Ref,
    string InstrumentIdentifier,
    string? InstrumentTitle,
    string Who,
    string MustDo,
    DirectiveType Type,
    DirectiveApplicability Applicability,
    DirectiveStatus Status,
    ByWhenKind ByWhenKind,
    DateTimeOffset? ResolvedDate,
    MandateTool? CrosswalkTarget,
    string? CrosswalkRef);
