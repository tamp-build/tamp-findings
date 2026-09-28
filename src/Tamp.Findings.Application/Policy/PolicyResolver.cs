using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Risk;

namespace Tamp.Findings.Application.Policy;

/// <summary>
/// Resolves the three-layer policy (ADR 0007) for a project or client into one
/// effective, hardened <see cref="EffectivePolicyLayer"/> with per-value
/// provenance. Read-only — this is what the policy SCREENS render; wiring the
/// merged result into gate evaluation is a separate, guarded step.
///
/// Backward compatibility (ADR 0007 §3): a project's existing gate settings live
/// in <see cref="Project.GatesConfig"/>, not the new <see cref="Project.PolicyLayer"/>.
/// The resolver bridges — it reads the project layer's gates and mode from
/// GatesConfig and the remaining hardenable fields from PolicyLayer — so nothing
/// has to be migrated and a project with no template, client layer or overlay
/// resolves to exactly its current flat config.
/// </summary>
public sealed class PolicyResolver(FindingsDbContext db)
{
    /// <summary>The full template → client → project stack for one project.</summary>
    public async Task<EffectivePolicyLayer> ForProjectAsync(Guid projectId, CancellationToken ct = default)
    {
        var project = await db.Projects.AsNoTracking()
            .Include(p => p.Client)
            .FirstOrDefaultAsync(p => p.Id == projectId, ct);
        if (project is null) return PolicyLayerMerge.Resolve([]);

        var layers = new List<(PolicyLayer, string)>();
        await AddTemplateAndClientAsync(project.Client, layers, ct);
        layers.Add((ProjectLayer(project), "this project"));
        return PolicyLayerMerge.Resolve(layers);
    }

    /// <summary>The merged effective gates for a project, projected back into the
    /// <see cref="ProjectGatesConfig"/> shape the evaluator and the hub consume.
    /// For a project with no template or client layer this reproduces its own
    /// GatesConfig exactly, so callers can swap it in behaviour-preservingly.</summary>
    public async Task<ProjectGatesConfig> EffectiveGatesAsync(
        Guid projectId, ProjectGatesConfig? original, CancellationToken ct = default)
    {
        var layer = await ForProjectAsync(projectId, ct);
        return ToGatesConfig(layer, original);
    }

    /// <summary>Project the merged layer's gates into a ProjectGatesConfig. Only
    /// enabled gates carry — GateEvaluator treats an absent key as off, exactly
    /// as today — and SchemaVersion / the enforcement-mode override are carried
    /// from the project's own config (mode resolution stays with
    /// EnforcementResolver).</summary>
    public static ProjectGatesConfig ToGatesConfig(EffectivePolicyLayer layer, ProjectGatesConfig? original)
    {
        var cfg = new ProjectGatesConfig
        {
            SchemaVersion = original?.SchemaVersion ?? 1,
            EnforcementMode = original?.EnforcementMode,
        };
        foreach (var (key, g) in layer.Gates)
            if (g.Enabled)
                cfg.Gates[key] = new GateConfig { Enabled = true, Threshold = g.Threshold };
        return cfg;
    }

    /// <summary>The template → client stack for one client (no project layer).</summary>
    public async Task<EffectivePolicyLayer> ForClientAsync(Guid clientId, CancellationToken ct = default)
    {
        var client = await db.Clients.AsNoTracking().FirstOrDefaultAsync(c => c.Id == clientId, ct);
        if (client is null) return PolicyLayerMerge.Resolve([]);

        var layers = new List<(PolicyLayer, string)>();
        await AddTemplateAndClientAsync(client, layers, ct);
        return PolicyLayerMerge.Resolve(layers);
    }

    private async Task AddTemplateAndClientAsync(Client? client, List<(PolicyLayer, string)> layers, CancellationToken ct)
    {
        if (client is null) return;

        if (client.PolicyTemplateId is { } tid)
        {
            var tpl = await db.PolicyTemplates.AsNoTracking().FirstOrDefaultAsync(t => t.Id == tid, ct);
            if (tpl is not null) layers.Add((tpl.Layer, tpl.Label));
        }
        if (client.PolicyLayer is { } clientLayer)
            layers.Add((clientLayer, client.Name));
    }

    // The project's layer, bridged from where its data currently lives: gates and
    // mode from GatesConfig, the rest from the new overlay.
    private static PolicyLayer ProjectLayer(Project p) => new()
    {
        Mode = p.GatesConfig?.EnforcementMode ?? p.PolicyLayer?.Mode,
        Gates = p.GatesConfig?.Gates ?? new(),
        RequiredScanners = p.PolicyLayer?.RequiredScanners ?? [],
        DeniedLicenses = p.PolicyLayer?.DeniedLicenses ?? [],
        PoamDeadlineDays = p.PolicyLayer?.PoamDeadlineDays ?? new(),
    };
}
