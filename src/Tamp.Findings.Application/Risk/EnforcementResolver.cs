using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Risk;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Application.Risk;

// Resolves the effective enforcement mode for a project (ADR 0004; TFND-148 /
// TFND-149). Loads the instance floor + lock, the client override and the
// project override, then defers to the pure EnforcementResolution.
//
// The CLI gate (TFND-150) and the check publisher read this so both surfaces
// agree on whether a blocking verdict actually fails the build.
public sealed class EnforcementResolver
{
    private readonly FindingsDbContext _db;
    private readonly InstanceEnforcementPolicy _policy;

    public EnforcementResolver(FindingsDbContext db, InstanceEnforcementPolicy policy)
    {
        _db = db;
        _policy = policy;
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

        var proj = await _db.Projects.AsNoTracking()
            .Where(p => p.Id == projectId)
            .Select(p => new { p.GatesConfig, ClientMode = p.Client!.EnforcementMode })
            .SingleOrDefaultAsync(ct);

        var projectMode = proj?.GatesConfig?.EnforcementMode;
        var clientMode = proj?.ClientMode;

        return EnforcementResolution.Resolve(instanceMode, instanceLocked, clientMode, projectMode);
    }
}
