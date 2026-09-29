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

public sealed record RulesPushResult(int Upserted, int Retired, int Active, IReadOnlyList<SupersededPoamRef> Superseded)
{
    public RulesPushResult(int upserted, int retired, int active) : this(upserted, retired, active, []) { }
}

/// <summary>A mandate POA&amp;M auto-closed by a push because the reviewed rule that raised it
/// is no longer active+Reviewed (TFND-196). Carried out so the ingest surface can audit it.</summary>
public sealed record SupersededPoamRef(Guid PoamId, string MandateId, string Reason);

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
    //
    // Rule-supersession lifecycle (TFND-196): a generation can invalidate the human review a
    // rule had. When a rule's CONTENT changes at the same key, its Reviewed status is forced
    // back to Draft — a regenerated check is unreviewed until a human re-approves it; the
    // generator cannot self-certify. Any open mandate POA&M then left without an active,
    // Reviewed rule mapping its mandate is auto-superseded (closed with an audited reason),
    // so an invalidated or retired mapping does not strand a dated POA&M against an AO.
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

            var isNew = !byKey.TryGetValue((dto.AdrRef, dto.RuleId), out var rule);
            // Compare content BEFORE overwriting: a real change (not the generation sha, which
            // churns every push) forces the rule back to Draft regardless of what the DTO claims.
            var contentChanged = !isNew && ContentChanged(rule!, dto);
            var prevStatus = rule?.ReviewStatus ?? ReviewStatus.Draft;

            if (isNew)
            {
                rule = new ConformanceRule { ProjectId = projectId, AdrRef = dto.AdrRef, RuleId = dto.RuleId };
                db.ConformanceRules.Add(rule);
                byKey[(dto.AdrRef, dto.RuleId)] = rule;
            }
            rule!.Intent = dto.Intent;
            rule.Method = Parse(dto.Method, ConformanceMethod.Deterministic);
            rule.CheckSpec = dto.CheckSpec;
            rule.ControlRefs = dto.ControlRefs ?? [];
            rule.ZtPillar = dto.ZtPillar;
            rule.ZtFunction = dto.ZtFunction;
            rule.ZtStage = dto.ZtStage;
            rule.MandateId = dto.MandateId;
            rule.RulesSha = dto.RulesSha ?? generation.GenerationSha;
            rule.ExtractionModelId = generation.ExtractionModelId;
            // Forced to Draft on a content change; a new rule takes the DTO's claim (Draft by
            // default); an unchanged rule PRESERVES the human review it already had, so a re-push
            // that omits reviewStatus cannot silently un-review a rule.
            rule.ReviewStatus = contentChanged
                ? ReviewStatus.Draft
                : Parse(dto.ReviewStatus, isNew ? ReviewStatus.Draft : prevStatus);
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

        // Which mandates are still backed by an active, Reviewed rule after this push. A mandate
        // POA&M is legitimate only while such a mapping exists; a content change (→ Draft) or a
        // retirement drops the mandate out of this set.
        var coveredMandates = byKey.Values
            .Where(r => r.RetiredAt is null && r.ReviewStatus == ReviewStatus.Reviewed && !string.IsNullOrWhiteSpace(r.MandateId))
            .Select(r => r.MandateId!)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var superseded = await SupersedeOrphanedMandatePoamsAsync(projectId, coveredMandates, generation.GenerationSha, now, ct);

        await db.SaveChangesAsync(ct);
        var active = await db.ConformanceRules.CountAsync(r => r.ProjectId == projectId && r.RetiredAt == null, ct);
        return new RulesPushResult(upserted, retired, active, superseded);
    }

    // Close (Cancelled) any open mandate POA&M whose mandate is no longer mapped by an active,
    // Reviewed rule (TFND-196). By construction a mandate POA&M implies there WAS a reviewed
    // mapping; once it is gone the item's basis no longer holds, so it is superseded rather than
    // left open forever (closure of a live weakness stays human-owned — this only closes ones
    // the rule change invalidated). The reason is stamped on the item (for the AO) and audited.
    private async Task<IReadOnlyList<SupersededPoamRef>> SupersedeOrphanedMandatePoamsAsync(
        Guid projectId, HashSet<string> coveredMandates, string? generationSha, DateTimeOffset now, CancellationToken ct)
    {
        var openMandatePoams = await db.PoamItems
            .Where(p => p.ProjectId == projectId && p.ClosedAt == null
                && (p.SourceKind == PoamSource.OperationalMandate || p.SourceKind == PoamSource.SupplyChainMandate)
                && p.SourceRef != null)
            .ToListAsync(ct);

        var orphaned = openMandatePoams.Where(p => !coveredMandates.Contains(p.SourceRef!)).ToList();
        if (orphaned.Count == 0) return [];

        var clientId = await db.Projects.Where(p => p.Id == projectId).Select(p => p.ClientId).FirstOrDefaultAsync(ct);
        var scope = new ScopeTarget(clientId, projectId, null);
        var gen = string.IsNullOrWhiteSpace(generationSha) ? "a new rule generation" : $"generation '{generationSha}'";
        var result = new List<SupersededPoamRef>(orphaned.Count);

        foreach (var poam in orphaned)
        {
            var reason = $"Superseded by {gen}: the reviewed conformance rule that mandate "
                + $"'{poam.SourceRef}' was raised against is no longer active and Reviewed "
                + "(its content was regenerated, or the rule was retired). This POA&M is cancelled "
                + "because its basis no longer holds; if the mandate still fails under the new rule "
                + "set, a fresh POA&M is raised once the new rule is reviewed.";

            poam.Status = PoamStatus.Cancelled;
            poam.ClosedAt = now;
            poam.ActualCompletionDate = now;
            poam.UpdatedAt = now;
            poam.WeaknessDescription += $"\n\n---\n{reason}";

            audit.RecordSystem(AuditActions.MandatePoamSuperseded, AuditClass.Risk, scope,
                subjectId: poam.Id, subjectKind: nameof(PoamItem),
                detail: $"{poam.SourceRef}: {reason}");
            result.Add(new SupersededPoamRef(poam.Id, poam.SourceRef!, reason));
        }
        return result;
    }

    // A real content change — the fields a human reviews — not the per-push generation sha.
    //
    // Findings owns whether its stored review is still valid; it does NOT assume the producer's
    // content hash covers everything findings reviews. The generator's per-rule RulesSha is a
    // precise signal for what it DOES hash (tamp's is sha256 over checkSpec + ruleId + intent),
    // so it's used for those; but the method and the mapping annotations (which mandate, which
    // controls, which ZT function a verdict gates) are reviewed content too and are NOT in that
    // hash — so they are always compared directly, regardless of the RulesSha. That keeps
    // re-review correct against any producer, whatever its hash happens to include.
    private static bool ContentChanged(ConformanceRule existing, AdrRuleDto dto)
    {
        // Reviewed fields outside the producer's content hash — always checked directly.
        if (existing.Method != Parse(dto.Method, ConformanceMethod.Deterministic)
            || existing.MandateId != dto.MandateId
            || existing.ZtPillar != dto.ZtPillar
            || existing.ZtFunction != dto.ZtFunction
            || existing.ZtStage != dto.ZtStage
            || !new HashSet<string>(existing.ControlRefs, StringComparer.Ordinal).SetEquals(dto.ControlRefs ?? []))
            return true;

        // The checkable content: the per-rule hash when supplied, else the fields themselves.
        if (!string.IsNullOrWhiteSpace(dto.RulesSha))
            return !string.Equals(existing.RulesSha, dto.RulesSha, StringComparison.OrdinalIgnoreCase);
        return existing.CheckSpec != dto.CheckSpec || existing.Intent != dto.Intent;
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
