using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Application.Auditing;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Projects;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Compliance;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Application.Compliance;

// The authoritative conformance-rules store (TFND-190 / ADR 0012): the generation-push
// write side and the ruleset-fetch read side. A push replaces a project's active rule
// set (upsert + retire-missing, never hard-delete); the fetch serves the active set the
// analyzer runs.

// ── Push (generation) wire shapes ──
public sealed class AdrRuleGeneration
{
    public string? GenerationSha { get; set; }
    public string? ExtractionModelId { get; set; }
    public List<AdrRuleDto> Rules { get; set; } = [];
}

public sealed class AdrRuleDto
{
    public required string AdrRef { get; set; }
    public required string RuleId { get; set; }
    public string? Intent { get; set; }
    public string? Method { get; set; }            // deterministic | semantic | verify
    public string? CheckSpec { get; set; }
    public List<string>? ControlRefs { get; set; }
    public string? ZtPillar { get; set; }
    public string? ZtFunction { get; set; }
    public int? ZtStage { get; set; }
    public string? MandateId { get; set; }
    public string? RulesSha { get; set; }
    public string? ReviewStatus { get; set; }      // Draft | Reviewed
}

public sealed record RulesPushResult(int Upserted, int Retired, int Active);

public sealed class ConformanceRulesService(FindingsDbContext db, CapabilityEvaluator capabilities, AuditLog audit)
{
    // Human review of a conformance rule (TFND-194 / ADR 0006 §, ADR 0012 §4). Promoting a
    // rule Draft→Reviewed is what lets its verdict block a build (TFND-191) or raise a mandate
    // POA&M (TFND-192). Gated on EditGates — conformance rules are the conformance contract,
    // the same class of decision as the release gates (Admin + InfoSec).
    public async Task<Result<Guid>> SetReviewStatusAsync(
        Principal actor, ScopeTarget scope, Guid projectId, string adrRef, string ruleId,
        ReviewStatus status, CancellationToken ct = default)
    {
        var decision = capabilities.Evaluate(actor, Capability.EditGates);
        if (!decision.Allowed) return Result<Guid>.Denied(decision.Reason!);

        var rule = await db.ConformanceRules.FirstOrDefaultAsync(
            r => r.ProjectId == projectId && r.AdrRef == adrRef && r.RuleId == ruleId && r.RetiredAt == null, ct);
        if (rule is null) return Result<Guid>.Invalid("That rule no longer exists on this project.");
        if (rule.ReviewStatus == status) return Result<Guid>.Ok(rule.Id);

        rule.ReviewStatus = status;
        audit.Record(actor, "conformance_rule.reviewed", AuditClass.Risk, scope,
            subjectId: rule.Id, subjectKind: nameof(ConformanceRule), detail: $"{adrRef}/{ruleId} → {status}");
        await db.SaveChangesAsync(ct);
        return Result<Guid>.Ok(rule.Id);
    }

    /// <summary>Promote every Draft rule (optionally only within one ADR) to Reviewed — the
    /// bulk "I've reviewed this ADR's rules" action. Returns how many were promoted.</summary>
    public async Task<Result<int>> PromoteDraftAsync(
        Principal actor, ScopeTarget scope, Guid projectId, string? adrRef, CancellationToken ct = default)
    {
        var decision = capabilities.Evaluate(actor, Capability.EditGates);
        if (!decision.Allowed) return Result<int>.Denied(decision.Reason!);

        var q = db.ConformanceRules.Where(r => r.ProjectId == projectId && r.RetiredAt == null
            && r.ReviewStatus == ReviewStatus.Draft);
        if (adrRef is { Length: > 0 }) q = q.Where(r => r.AdrRef == adrRef);
        var drafts = await q.ToListAsync(ct);

        foreach (var r in drafts) r.ReviewStatus = ReviewStatus.Reviewed;
        if (drafts.Count > 0)
        {
            audit.Record(actor, "conformance_rule.reviewed", AuditClass.Risk, scope,
                subjectId: projectId, subjectKind: nameof(ConformanceRule),
                detail: $"promoted {drafts.Count} rule(s){(adrRef is { Length: > 0 } ? " in " + adrRef : "")} to Reviewed");
            await db.SaveChangesAsync(ct);
        }
        return Result<int>.Ok(drafts.Count);
    }

    // Replace a project's active rule set with the pushed generation (ADR 0012 §2).
    // Idempotent: upsert by (AdrRef, RuleId), un-retire on re-appearance, retire any active
    // rule the generation drops. Rules are never hard-deleted (a past verdict cites RulesSha).
    public async Task<RulesPushResult> PushAsync(Guid projectId, AdrRuleGeneration generation, CancellationToken ct = default)
    {
        var existing = await db.ConformanceRules.Where(r => r.ProjectId == projectId).ToListAsync(ct);
        var byKey = existing.ToDictionary(r => (r.AdrRef, r.RuleId), KeyComparer.Ordinal);

        var pushedKeys = new HashSet<(string, string)>(KeyComparer.Ordinal);
        var now = DateTimeOffset.UtcNow;
        var upserted = 0;

        foreach (var dto in generation.Rules)
        {
            if (string.IsNullOrWhiteSpace(dto.AdrRef) || string.IsNullOrWhiteSpace(dto.RuleId)) continue;
            pushedKeys.Add((dto.AdrRef, dto.RuleId));

            if (!byKey.TryGetValue((dto.AdrRef, dto.RuleId), out var rule))
            {
                rule = new ConformanceRule { ProjectId = projectId, AdrRef = dto.AdrRef, RuleId = dto.RuleId };
                db.ConformanceRules.Add(rule);
                byKey[(dto.AdrRef, dto.RuleId)] = rule;
            }
            rule.Intent = dto.Intent;
            rule.Method = Parse(dto.Method, ConformanceMethod.Deterministic);
            rule.CheckSpec = dto.CheckSpec;
            rule.ControlRefs = dto.ControlRefs ?? [];
            rule.ZtPillar = dto.ZtPillar;
            rule.ZtFunction = dto.ZtFunction;
            rule.ZtStage = dto.ZtStage;
            rule.MandateId = dto.MandateId;
            rule.RulesSha = dto.RulesSha ?? generation.GenerationSha;
            rule.ExtractionModelId = generation.ExtractionModelId;
            rule.ReviewStatus = Parse(dto.ReviewStatus, ReviewStatus.Draft);
            rule.RetiredAt = null;   // (re)active
            rule.PushedAt = now;
            upserted++;
        }

        // Retire active rules the generation no longer contains.
        var retired = 0;
        foreach (var r in existing)
            if (r.RetiredAt is null && !pushedKeys.Contains((r.AdrRef, r.RuleId)))
            {
                r.RetiredAt = now;
                retired++;
            }

        await db.SaveChangesAsync(ct);
        var active = await db.ConformanceRules.CountAsync(r => r.ProjectId == projectId && r.RetiredAt == null, ct);
        return new RulesPushResult(upserted, retired, active);
    }

    private static TEnum Parse<TEnum>(string? value, TEnum fallback) where TEnum : struct
        => Enum.TryParse<TEnum>(value, ignoreCase: true, out var v) ? v : fallback;

    private sealed class KeyComparer : IEqualityComparer<(string, string)>
    {
        public static readonly KeyComparer Ordinal = new();
        public bool Equals((string, string) a, (string, string) b) =>
            string.Equals(a.Item1, b.Item1, StringComparison.OrdinalIgnoreCase)
            && string.Equals(a.Item2, b.Item2, StringComparison.OrdinalIgnoreCase);
        public int GetHashCode((string, string) x) =>
            HashCode.Combine(x.Item1.ToLowerInvariant(), x.Item2.ToLowerInvariant());
    }
}

// ── Fetch (ruleset) read side ──
public sealed class ConformanceRulesQuery(FindingsDbContext db)
{
    public const string SchemaVersion = "1.0";

    /// <summary>The project's ACTIVE rule set — what the analyzer runs (ADR 0012 §3).</summary>
    public async Task<AdrRuleset> ForProjectAsync(Guid projectId, CancellationToken ct = default)
    {
        var rules = await db.ConformanceRules.AsNoTracking()
            .Where(r => r.ProjectId == projectId && r.RetiredAt == null)
            .OrderBy(r => r.AdrRef).ThenBy(r => r.RuleId)
            .Select(r => new AdrRuleView(
                r.AdrRef, r.RuleId, r.Intent, r.Method.ToString(), r.CheckSpec, r.ControlRefs,
                r.ZtPillar, r.ZtFunction, r.ZtStage, r.MandateId, r.RulesSha, r.ReviewStatus.ToString()))
            .ToListAsync(ct);

        return new AdrRuleset(SchemaVersion, projectId, rules, DateTimeOffset.UtcNow);
    }
}

public sealed record AdrRuleset(string SchemaVersion, Guid ProjectId, IReadOnlyList<AdrRuleView> Rules, DateTimeOffset AsOf);
public sealed record AdrRuleView(
    string AdrRef, string RuleId, string? Intent, string Method, string? CheckSpec,
    IReadOnlyList<string> ControlRefs, string? ZtPillar, string? ZtFunction, int? ZtStage,
    string? MandateId, string? RulesSha, string ReviewStatus);
