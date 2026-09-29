using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Application.Auditing;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Projects;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Risk;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Application.Policy;

// A distributable POLICY CONTENT PACK (TFND-203 phase B). Baseline policy templates are the
// source of truth in the DB, described by a versioned pack (JSON). An admin applies a pack — a
// DB update — so a baseline change ships WITHOUT an app republish. The startup code seeder is the
// first-boot BOOTSTRAP; ongoing updates come through here.
//
// An applied template is marked NOT seeded and its Version bumped, so the code seeder (which only
// refreshes an untouched IsSeeded && Version==1 seed) leaves a pack-managed template alone — the
// pack wins over the shipped bootstrap. Idempotent: a template whose layer + scoring already match
// the pack is left untouched (no version churn).
public sealed class PolicyPackService(FindingsDbContext db, CapabilityEvaluator capabilities, AuditLog audit)
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public async Task<Result<PolicyPackResult>> ApplyAsync(
        Principal actor, PolicyPack pack, CancellationToken ct = default)
    {
        var decision = capabilities.Evaluate(actor, Capability.EditPolicyWeights);
        if (!decision.Allowed) return Result<PolicyPackResult>.Denied(decision.Reason!);
        if (pack.Templates.Count == 0)
            return Result<PolicyPackResult>.Invalid("The pack contains no templates.");

        var defaultPolicyId = await db.RiskPolicies.AsNoTracking()
            .Where(p => p.IsDefault).Select(p => (Guid?)p.Id).FirstOrDefaultAsync(ct);
        var federalPolicyId = await db.RiskPolicies.AsNoTracking()
            .Where(p => p.Name == RiskPolicyDefaults.TampFederalV1Name).Select(p => (Guid?)p.Id).FirstOrDefaultAsync(ct);

        int created = 0, updated = 0, unchanged = 0;
        var now = DateTimeOffset.UtcNow;

        foreach (var t in pack.Templates)
        {
            if (string.IsNullOrWhiteSpace(t.Name) || t.Layer is null) continue;

            var scoring = t.Scoring?.Trim().ToLowerInvariant() switch
            {
                "federal" => federalPolicyId,
                _ => defaultPolicyId,   // default / null / anything else → the instance default
            };
            var incomingLayerJson = JsonSerializer.Serialize(t.Layer, Json);

            var existing = await db.PolicyTemplates.FirstOrDefaultAsync(x => x.Name == t.Name, ct);
            if (existing is null)
            {
                db.PolicyTemplates.Add(new PolicyTemplate
                {
                    Name = t.Name.Trim(), Version = 1, IsSeeded = false,
                    Layer = t.Layer, RiskPolicyId = scoring, CreatedByLogin = actor.Login,
                });
                created++;
            }
            else if (JsonSerializer.Serialize(existing.Layer, Json) != incomingLayerJson
                     || existing.RiskPolicyId != scoring)
            {
                existing.Layer = t.Layer;
                existing.RiskPolicyId = scoring;
                existing.Version += 1;      // bump so the code seeder leaves this pack-managed template alone
                existing.IsSeeded = false;  // now pack-managed, not code-seeded
                existing.UpdatedAt = now;
                updated++;
            }
            else
            {
                unchanged++;
            }
        }

        if (created + updated > 0)
        {
            // Risk class: it changes the baseline every client and project inherits.
            audit.Record(actor, "policy_pack.applied", AuditClass.Risk, ScopeTarget.Instance,
                subjectKind: "policy_pack",
                detail: $"pack {pack.PackVersion ?? "(unversioned)"}: {created} created, {updated} updated, {unchanged} unchanged");
            await db.SaveChangesAsync(ct);
        }

        return Result<PolicyPackResult>.Ok(new PolicyPackResult(pack.PackVersion, created, updated, unchanged));
    }
}

/// <summary>A distributable pack of baseline policy templates (TFND-203 phase B).</summary>
public sealed class PolicyPack
{
    public string? PackVersion { get; set; }
    public List<PolicyPackTemplate> Templates { get; set; } = [];
}

public sealed class PolicyPackTemplate
{
    public required string Name { get; set; }
    /// <summary>The hardenable overlay (mode / gates / required scanners / licences / poam / assertions).</summary>
    public required PolicyLayer Layer { get; set; }
    /// <summary>Which scoring RiskPolicy to link: "federal" → Tamp Federal, else the instance default.</summary>
    public string? Scoring { get; set; }
}

public sealed record PolicyPackResult(string? PackVersion, int Created, int Updated, int Unchanged);
