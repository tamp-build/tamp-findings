using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Risk;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Application.Risk;

// Resolves the effective enforcement mode for a project (ADR 0004; TFND-148 /
// TFND-149, corrected by TFND-247). Loads the instance floor + lock and the
// MERGED policy layer, then defers to the pure EnforcementResolution.
//
// It used to read Client.EnforcementMode — a legacy scalar that nothing has
// written since the policy layers landed, so the client arm was always null and
// a client-level mode authored through the UI did nothing. The merged layer is
// the authority now, which also means a template's mode finally applies.
//
// The CLI gate (TFND-150) and the check publisher read this so both surfaces
// agree on whether a blocking verdict actually fails the build.
public sealed class EnforcementResolver
{
    private readonly FindingsDbContext _db;
    private readonly InstanceEnforcementPolicy _policy;
    private readonly Policy.PolicyResolver _layers;

    public EnforcementResolver(
        FindingsDbContext db, InstanceEnforcementPolicy policy, Policy.PolicyResolver layers)
    {
        _db = db;
        _policy = policy;
        _layers = layers;
    }

    public async Task<EnforcementMode> ForProjectAsync(Guid projectId, CancellationToken ct = default)
    {
        var settings = await _db.InstanceSettings.AsNoTracking()
            .Where(s => s.Id == InstanceSettings.SingletonId)
            .Select(s => new { s.EnforcementMode, s.EnforcementLocked })
            .SingleOrDefaultAsync(ct);

        // No settings row yet → advisory/unlocked, the safe default. The config
        // lock (if any) overrides the stored values.
        var (instanceMode, instanceLocked) = _policy.Effective(
            settings?.EnforcementMode ?? EnforcementMode.Advisory,
            settings?.EnforcementLocked ?? false);

        // The strictest mode any layer authored, with provenance. PolicyResolver
        // bridges the project's own override from GatesConfig, so a per-project
        // Enforcing is in here too — there is nothing left to read separately.
        var merged = await _layers.ForProjectAsync(projectId, ct);

        return EnforcementResolution.Resolve(instanceMode, instanceLocked, merged.Mode?.Value);
    }
}
