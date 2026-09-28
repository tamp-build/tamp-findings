using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Application.Policy;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Compliance;

namespace Tamp.Findings.Application.Compliance;

/// <summary>
/// Resolves a project's control coverage (TFND-185 / ADR 0009): every in-scope
/// control's disposition (gated / inherited / n/a / unmapped), computed from the
/// project's baseline ∩ the effective policy assertions ∩ (optionally) a build's
/// component capability. The disposition is DERIVED, never stored, so it cannot
/// drift from the catalog or the templates — the same guarantee as the in-scope
/// control set in <see cref="ComplianceProfileQuery"/>.
/// </summary>
public sealed class ControlDispositionQuery(FindingsDbContext db, PolicyResolver resolver)
{
    /// <summary>
    /// The coverage for a project, or null when it has no compliance framework
    /// assigned or no current catalog — the no-unmapped meta-gate reads null as
    /// Unknown, and the profile view omits the coverage block.
    /// </summary>
    /// <param name="capability">
    /// A build's aggregate component capability, when computing coverage for a
    /// specific build (the gate decision + dashboard). Null for the
    /// build-independent profile view — a Gated control then stays Gated rather
    /// than resolving to N/A on capability.
    /// </param>
    public async Task<ControlCoverage?> ForProjectAsync(
        Guid projectId, ComponentCapability? capability, CancellationToken ct = default)
    {
        var project = await db.Projects.AsNoTracking()
            .Include(p => p.Client)
            .FirstOrDefaultAsync(p => p.Id == projectId, ct);
        if (project is null) return null;

        // Framework is inherited from the client (same resolution as the profile).
        var fid = project.Client?.FrameworkId;
        if (fid is null) return null;
        var fw = await db.Frameworks.AsNoTracking().FirstOrDefaultAsync(f => f.Id == fid, ct);
        if (fw is null || fw.Baseline == BaselineLevel.None) return null;

        var catalog = await db.ControlCatalogs.AsNoTracking().FirstOrDefaultAsync(c => c.IsCurrent, ct);
        if (catalog is null) return null;

        var inScope = catalog.Controls
            .Where(c => c.InBaseline(fw.Baseline))
            .OrderBy(c => c.Family).ThenBy(c => c.Id, StringComparer.Ordinal)
            .ToList();

        // The merged effective assertions across the template → client → project
        // stack (ADR 0007 provenance carried through).
        var effective = await resolver.ForProjectAsync(projectId, ct);

        return ControlDispositionResolver.Resolve(inScope, effective.Assertions, capability);
    }
}
