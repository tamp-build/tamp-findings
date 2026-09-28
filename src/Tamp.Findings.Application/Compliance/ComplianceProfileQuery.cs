using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Application.Policy;
using Tamp.Findings.Application.Risk;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Compliance;
using Tamp.Findings.Domain.Risk;

namespace Tamp.Findings.Application.Compliance;

/// <summary>
/// Builds a project's compliance profile (TFND-177) for the ingest-token read
/// endpoint: the framework the project is held to, its applicable controls, the
/// effective policy templates and the enforcement posture. Read-only. Exposes no
/// findings, no secrets, no other project — only what a conformance producer
/// needs to tag evidence with the correct control vocabulary for THIS project.
///
/// The applicable controls are COMPUTED from the assigned framework's baseline
/// against the current catalog's membership flags (ADR 0007 / v3 §6), so they
/// cannot drift from the catalog.
/// </summary>
public sealed class ComplianceProfileQuery(
    FindingsDbContext db, PolicyResolver resolver, EnforcementResolver enforcement)
{
    // 1.1 (TFND-185): additive — per-control Disposition + a Coverage roll-up.
    // Consumers on 1.0 ignore the new fields (ADR 0018 additive-only).
    public const string SchemaVersion = "1.1";

    /// <summary>The profile, or null when the project does not exist or has no
    /// profile configured (no framework AND no inherited policy template) — the
    /// endpoint maps null to 404.</summary>
    public async Task<ComplianceProfile?> ForProjectAsync(Guid projectId, CancellationToken ct = default)
    {
        var project = await db.Projects.AsNoTracking()
            .Include(p => p.Client)
            .FirstOrDefaultAsync(p => p.Id == projectId, ct);
        if (project is null) return null;

        var client = project.Client;

        // Framework (inherited from the client) + its applicable controls.
        Domain.Entities.Framework? fw = client?.FrameworkId is { } fid
            ? await db.Frameworks.AsNoTracking().FirstOrDefaultAsync(f => f.Id == fid, ct)
            : null;

        var controls = new List<ProfileControl>();
        ProfileCoverage? coverage = null;
        if (fw is not null && fw.Baseline != BaselineLevel.None)
        {
            var catalog = await db.ControlCatalogs.AsNoTracking().FirstOrDefaultAsync(c => c.IsCurrent, ct);
            if (catalog is not null)
            {
                var inScope = catalog.Controls
                    .Where(c => c.InBaseline(fw.Baseline))
                    .OrderBy(c => c.Family).ThenBy(c => c.Id, StringComparer.Ordinal)
                    .ToList();

                // Disposition each in-scope control (TFND-185 / ADR 0009), reusing
                // the controls already loaded. Build-independent (null capability):
                // the profile is what the project is held to, not any one build.
                var effective = await resolver.ForProjectAsync(projectId, ct);
                var resolved = Domain.Compliance.ControlDispositionResolver.Resolve(
                    inScope, effective.Assertions, capability: null);

                controls = resolved.Controls
                    .Select(c => new ProfileControl(c.ControlId, c.Title, c.Family, c.Disposition.ToString()))
                    .ToList();
                coverage = new ProfileCoverage(
                    resolved.InScope, resolved.Gated, resolved.Inherited,
                    resolved.NotApplicable, resolved.Unmapped);
            }
        }

        // Enforcement posture (Project → Client → Instance, with the locked floor).
        var mode = await enforcement.ForProjectAsync(projectId, ct);
        var locked = await db.InstanceSettings.AsNoTracking()
            .Select(s => s.EnforcementLocked).FirstOrDefaultAsync(ct);

        // The effective policy templates. There is at most one inherited template
        // today; its gates are the effective enabled gate set for this project.
        var templates = new List<ProfileTemplate>();
        if (client?.PolicyTemplateId is { } tid)
        {
            var tpl = await db.PolicyTemplates.AsNoTracking().FirstOrDefaultAsync(t => t.Id == tid, ct);
            if (tpl is not null)
            {
                var gates = await resolver.EffectiveGatesAsync(projectId, project.GatesConfig, ct);
                var gateKeys = gates.Gates.Where(g => g.Value.Enabled).Select(g => g.Key)
                    .OrderBy(k => k, StringComparer.Ordinal).ToArray();
                templates.Add(new ProfileTemplate(tpl.Id.ToString(), tpl.Label, gateKeys, mode.ToString(), locked));
            }
        }

        // A project with neither a framework nor an inherited template has no
        // profile configured — 404, not an empty 200.
        if (fw is null && templates.Count == 0) return null;

        return new ComplianceProfile(
            SchemaVersion,
            project.Id,
            project.Name,
            fw is null ? null : new ProfileFramework(fw.Slug, fw.Name, fw.Version),
            controls,
            templates,
            new ProfileEnforcement(mode.ToString(), locked),
            DateTimeOffset.UtcNow,
            coverage);
    }
}

public sealed record ComplianceProfile(
    string SchemaVersion, Guid ProjectId, string ProjectName,
    ProfileFramework? Framework, IReadOnlyList<ProfileControl> Controls,
    IReadOnlyList<ProfileTemplate> PolicyTemplates, ProfileEnforcement Enforcement, DateTimeOffset AsOf,
    // TFND-185: the control-disposition roll-up (null when no framework/catalog).
    ProfileCoverage? Coverage = null);

public sealed record ProfileFramework(string Id, string Name, string Version);
// Disposition (TFND-185): "Gated" | "Inherited" | "NotApplicable" | "Unmapped",
// or null on a profile with no framework. Additive to the tamp contract (ADR 0018).
public sealed record ProfileControl(string Id, string Title, string Family, string? Disposition = null);
public sealed record ProfileCoverage(int InScope, int Gated, int Inherited, int NotApplicable, int Unmapped);
public sealed record ProfileTemplate(string Id, string Name, IReadOnlyList<string> Gates, string Enforcement, bool Locked);
public sealed record ProfileEnforcement(string Mode, bool Locked);
