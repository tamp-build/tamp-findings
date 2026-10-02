using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Risk;

namespace Tamp.Findings.Application.Risk;

/// <summary>
/// THE one place that decides which scoring <see cref="Tamp.Findings.Domain.Entities.RiskPolicy"/>
/// a project's score is computed against — the weights and bands, distinct from the compliance
/// template (gates + control coverage) resolved by <c>PolicyResolver</c>.
///
/// The resolution walks the hierarchy so the compliance baseline actually drives the score:
///   project override → client override → the client's compliance TEMPLATE's linked policy → default.
///
/// The template link is the load-bearing tier and the one every ad-hoc resolver used to skip:
/// a client on FedRAMP High (whose template links "Tamp Federal v1") must SCORE as federal, not
/// silently fall through to the instance default "Tamp Standard v1".
/// </summary>
public sealed class ScoringPolicyResolver
{
    private readonly FindingsDbContext _db;

    public ScoringPolicyResolver(FindingsDbContext db) => _db = db;

    /// <summary>The stored policy row for a project (or, with no project, a client): project override →
    /// client override → the client's template link → instance default. No archetype adjustment — this
    /// is the policy as authored, what a fork or an "effective policy" view should show. Null only if
    /// no RiskPolicy rows exist at all.</summary>
    public async Task<RiskPolicy?> ResolveRowAsync(Guid? clientId, Guid? projectId, CancellationToken ct = default)
    {
        Guid? id = null;
        if (projectId is { } prj)
        {
            var project = await _db.Projects.AsNoTracking()
                .Where(p => p.Id == prj)
                .Select(p => new { p.ClientId, p.RiskPolicyId })
                .FirstOrDefaultAsync(ct);
            id = project?.RiskPolicyId;
            clientId ??= project?.ClientId;
        }

        if (id is null && clientId is { } cid)
        {
            var client = await _db.Clients.AsNoTracking()
                .Where(c => c.Id == cid)
                .Select(c => new { c.RiskPolicyId, c.PolicyTemplateId })
                .FirstOrDefaultAsync(ct);

            // Client's own override first, then its compliance template's scoring link — this is
            // the tier every ad-hoc resolver skipped, so a FedRAMP-High client silently scored
            // against the instance default instead of the template's federal policy.
            id = client?.RiskPolicyId;
            if (id is null && client?.PolicyTemplateId is { } templateId)
            {
                id = await _db.PolicyTemplates.AsNoTracking()
                    .Where(t => t.Id == templateId)
                    .Select(t => t.RiskPolicyId)
                    .FirstOrDefaultAsync(ct);
            }
        }

        var policy = id is { } pid
            ? await _db.RiskPolicies.AsNoTracking().FirstOrDefaultAsync(p => p.Id == pid, ct)
            : null;
        return policy ?? await _db.RiskPolicies.AsNoTracking().FirstOrDefaultAsync(p => p.IsDefault, ct);
    }

    public async Task<ScoringPolicy> ForProjectAsync(Guid projectId, CancellationToken ct = default)
    {
        var archetype = await _db.Projects.AsNoTracking()
            .Where(p => p.Id == projectId)
            .Select(p => p.Archetype)
            .FirstOrDefaultAsync(ct);
        var policy = await ResolveRowAsync(null, projectId, ct);

        // No policy at all should be impossible — Program.cs seeds one — but falling back to the
        // built-in defaults beats throwing on a screen whose whole job is to report posture.
        var (id2, name, config) = policy is null
            ? ((Guid?)null, "Tamp Standard v1", RiskPolicyDefaults.BuildTampStandardV1())
            : (policy.Id, policy.Name, policy.Config);

        // Make the score archetype-aware: categories the component cannot produce evidence for
        // (IaC for a library, DAST/base-image for anything that isn't a running service) are
        // dropped from the weight basis instead of sitting there as a permanent 0/N (TFND-203).
        ArchetypeScoring.ApplyCapability(config, ArchetypeLayers.Capability(archetype));

        return new ScoringPolicy(id2, name, config);
    }
}

/// <summary>The resolved scoring policy: its id (null for the built-in fallback), name, and config.</summary>
public sealed record ScoringPolicy(Guid? Id, string Name, RiskPolicyConfig Config);
