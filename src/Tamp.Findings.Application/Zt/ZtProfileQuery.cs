using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Application.Eo;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Application.Zt;

// Serves tamp-ztt the ruleset it runs against (TFND-188 / ADR 0010 §8, the "ztt is
// analysis-only" boundary): the current ZTMM model (what pillars/functions/stages to
// score) and the operational mandate definitions that are currently IN FORCE — with
// liveness driven by the EO registry (ADR 0011), the single source of truth for whether
// a mandate's directive is live as of today. ztt fetches this, scans repo+ADRs, and
// posts results back to /ingest/conformance. Read-only; ingest-token scoped like the
// compliance-profile.
public sealed class ZtProfileQuery(FindingsDbContext db, EoRegistryQuery eo)
{
    public const string SchemaVersion = "1.0";

    /// <summary>The ztt ruleset for a project, or null when no ZTMM model is loaded or
    /// the project's client is not ZT-scored (no MaturityModelId).</summary>
    public async Task<ZtProfile?> ForProjectAsync(Guid projectId, CancellationToken ct = default)
    {
        var project = await db.Projects.AsNoTracking().Include(p => p.Client)
            .FirstOrDefaultAsync(p => p.Id == projectId, ct);
        if (project?.Client is null || project.Client.MaturityModelId is null) return null;

        var model = await db.MaturityModelCatalogs.AsNoTracking().FirstOrDefaultAsync(m => m.IsCurrent, ct);
        if (model is null) return null;

        var pillars = model.Pillars
            .Select(p => new ZtProfilePillar(p.Id, p.Name,
                p.Functions.Select(f => new ZtProfileFunction(f.Id, f.Name, f.CrossCutting,
                    f.Stages.OrderBy(s => s.Stage).Select(s => new ZtProfileStage(s.Stage, s.Descriptor)).ToList())).ToList()))
            .ToList();

        // In-force mandate liveness comes from the EO registry: a mandate is live when
        // its crosswalked directive is Active as of now (a rescinded directive's mandate
        // goes dormant — the emit-but-flag-dormant contract).
        var inForceRefs = (await eo.InForceAsOfAsync(DateTimeOffset.UtcNow, ct))
            .Where(d => d.CrosswalkRef is not null)
            .Select(d => d.CrosswalkRef!)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var pack = await db.MandatePacks.AsNoTracking().FirstOrDefaultAsync(p => p.IsCurrent, ct);
        var mandates = (pack?.Mandates ?? [])
            .Where(m => m.Tool == MandateTool.Ztt)   // ztt only serves ztt's operational lane
            .Select(m => new ZtProfileMandate(
                m.MandateId, m.Title, m.ApplicabilityRule, m.DerivationRuleRef,
                InForce: m.DerivationRuleRef is not null && inForceRefs.Contains(m.DerivationRuleRef)))
            .ToList();

        return new ZtProfile(
            SchemaVersion, project.Id, project.Name,
            new ZtProfileModel(model.Name, model.Version, pillars),
            pack?.Version,
            mandates,
            DateTimeOffset.UtcNow);
    }
}

public sealed record ZtProfile(
    string SchemaVersion, Guid ProjectId, string ProjectName,
    ZtProfileModel Model, string? MandatePackVersion,
    IReadOnlyList<ZtProfileMandate> Mandates, DateTimeOffset AsOf);

public sealed record ZtProfileModel(string Name, string Version, IReadOnlyList<ZtProfilePillar> Pillars);
public sealed record ZtProfilePillar(string Id, string Name, IReadOnlyList<ZtProfileFunction> Functions);
public sealed record ZtProfileFunction(string Id, string Name, bool CrossCutting, IReadOnlyList<ZtProfileStage> Stages);
public sealed record ZtProfileStage(int Stage, string Descriptor);
public sealed record ZtProfileMandate(string Id, string Title, string? ApplicabilityRule, string? DerivationRuleRef, bool InForce);
