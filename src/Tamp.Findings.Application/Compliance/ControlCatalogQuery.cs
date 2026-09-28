using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Compliance;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Application.Compliance;

/// <summary>
/// Reads the current control catalog and the frameworks for the Control
/// frameworks screen and the control-statement panel (v3 §6). Read-only.
/// </summary>
public sealed class ControlCatalogQuery(FindingsDbContext db)
{
    /// <summary>The current catalog's metadata + control count, and how many
    /// prior versions are retained.</summary>
    public async Task<CatalogSummary?> CurrentCatalogAsync(CancellationToken ct = default)
    {
        var current = await db.ControlCatalogs.AsNoTracking()
            .FirstOrDefaultAsync(c => c.IsCurrent, ct);
        if (current is null) return null;

        var prior = await db.ControlCatalogs.CountAsync(c => !c.IsCurrent, ct);
        return new CatalogSummary(
            current.Name, current.Source, current.Version, current.OscalVersion,
            current.ImportedSha, current.ImportedAt, current.Controls.Count, prior);
    }

    /// <summary>Every control in the current catalog, ordered by family then id.</summary>
    public async Task<IReadOnlyList<Control>> ControlsAsync(CancellationToken ct = default)
    {
        var current = await db.ControlCatalogs.AsNoTracking().FirstOrDefaultAsync(c => c.IsCurrent, ct);
        return current is null
            ? []
            : current.Controls.OrderBy(c => c.Family).ThenBy(c => c.Id, StringComparer.Ordinal).ToArray();
    }

    /// <summary>One control by id (case-insensitive) from the current catalog.</summary>
    public async Task<Control?> ControlAsync(string id, CancellationToken ct = default)
    {
        var current = await db.ControlCatalogs.AsNoTracking().FirstOrDefaultAsync(c => c.IsCurrent, ct);
        return current?.Controls.FirstOrDefault(c => string.Equals(c.Id, id, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>All frameworks, current first then drafts, alphabetical within.</summary>
    public async Task<IReadOnlyList<Framework>> FrameworksAsync(CancellationToken ct = default) =>
        await db.Frameworks.AsNoTracking()
            .OrderBy(f => f.Status).ThenBy(f => f.Name)
            .ToListAsync(ct);
}

public sealed record CatalogSummary(
    string Name, string Source, string Version, string? OscalVersion,
    string? ImportedSha, DateTimeOffset ImportedAt, int ControlCount, int PriorVersions);
