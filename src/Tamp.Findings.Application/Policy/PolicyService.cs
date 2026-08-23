using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Application.Auditing;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Projects;
using Tamp.Findings.Application.Risk;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Risk;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Application.Policy;

/// <summary>
/// The policy library and editor (TFND-104 … TFND-106).
///
/// A risk policy is the definition of what "bad" means on this instance. Every
/// score on every screen is meaningless without knowing which policy produced
/// it, which is why editing one is an audited, capability-gated act and why
/// deleting one that projects still use is refused rather than cascaded.
/// </summary>
public sealed class PolicyService
{
    private readonly FindingsDbContext _db;
    private readonly CapabilityEvaluator _capabilities;
    private readonly AuditLog _audit;
    private readonly RiskInputsBuilder _inputs;

    public PolicyService(
        FindingsDbContext db, CapabilityEvaluator capabilities, AuditLog audit, RiskInputsBuilder inputs)
    {
        _db = db;
        _capabilities = capabilities;
        _audit = audit;
        _inputs = inputs;
    }

    public async Task<IReadOnlyList<PolicyCard>> LibraryAsync(CancellationToken ct = default)
    {
        var policies = await _db.RiskPolicies.AsNoTracking()
            .Select(p => new
            {
                p.Id, p.Name, p.Description, p.IsDefault, p.IsSeeded, p.Config, p.UpdatedAt,
            })
            .ToArrayAsync(ct);

        // A policy's usage count is what blocks deletion, so it is part of the
        // card rather than something the delete dialog discovers late.
        var projectUse = await _db.Projects.AsNoTracking()
            .Where(p => p.RiskPolicyId != null)
            .GroupBy(p => p.RiskPolicyId!.Value)
            .Select(g => new { PolicyId = g.Key, Count = g.Count() })
            .ToArrayAsync(ct);
        var clientUse = await _db.Clients.AsNoTracking()
            .Where(c => c.RiskPolicyId != null)
            .GroupBy(c => c.RiskPolicyId!.Value)
            .Select(g => new { PolicyId = g.Key, Count = g.Count() })
            .ToArrayAsync(ct);

        return policies
            .Select(p => new PolicyCard(
                p.Id, p.Name, p.Description, p.IsDefault, p.IsSeeded,
                p.Config.SchemaVersion,
                p.Config.Categories.Count(c => c.Value.Enabled),
                projectUse.FirstOrDefault(u => u.PolicyId == p.Id)?.Count ?? 0,
                clientUse.FirstOrDefault(u => u.PolicyId == p.Id)?.Count ?? 0,
                p.UpdatedAt))
            .OrderByDescending(p => p.IsDefault)
            .ThenBy(p => p.Name, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    public async Task<PolicyDetail?> LoadAsync(Guid policyId, CancellationToken ct = default)
    {
        var policy = await _db.RiskPolicies.AsNoTracking()
            .SingleOrDefaultAsync(p => p.Id == policyId, ct);
        if (policy is null) return null;

        // Deep-copied so the editor's pending edits cannot reach the tracked
        // entity. A half-edited policy leaking into a score would be silent.
        return new PolicyDetail(
            policy.Id, policy.Name, policy.Description, policy.IsDefault, policy.IsSeeded,
            Clone(policy.Config));
    }

    /// <summary>
    /// Save weights, gates thresholds and bands.
    ///
    /// A SEEDED policy is read-only. Not because the rows are precious, but
    /// because it is the reference every other policy was derived from, and an
    /// edited baseline makes "how does ours differ from the standard?"
    /// unanswerable. The editor disables its inputs; this refuses regardless,
    /// because a disabled input is a courtesy and this is the rule.
    /// </summary>
    public async Task<Result<Guid>> SaveAsync(
        Principal actor, Guid policyId, RiskPolicyConfig config, string name, string? description,
        CancellationToken ct = default)
    {
        var decision = _capabilities.Evaluate(actor, Capability.EditPolicyWeights);
        if (!decision.Allowed) return Result<Guid>.Denied(decision.Reason!);

        var policy = await _db.RiskPolicies.SingleOrDefaultAsync(p => p.Id == policyId, ct);
        if (policy is null) return Result<Guid>.Invalid("That policy no longer exists.");

        if (policy.IsSeeded)
            return Result<Guid>.Invalid(
                "System policies are read-only. Duplicate this one and edit the copy — that keeps "
                + "\"how does ours differ from the standard?\" answerable.");

        if (Validate(config) is { } invalid) return Result<Guid>.Invalid(invalid);

        name = name.Trim();
        if (name.Length == 0) return Result<Guid>.Invalid("A policy needs a name.");

        var clash = await _db.RiskPolicies.AnyAsync(
            p => p.Id != policyId && p.Name.ToLower() == name.ToLower(), ct);
        if (clash) return Result<Guid>.Invalid($"Another policy is already called \"{name}\".");

        policy.Name = name;
        policy.Description = string.IsNullOrWhiteSpace(description) ? null : description.Trim();
        policy.Config = config;
        policy.UpdatedAt = DateTimeOffset.UtcNow;

        // Risk class: a weight change moves every score under this policy, and
        // that is exactly the kind of decision an assessor reads first.
        _audit.Record(actor, AuditActions.PolicySaved, AuditClass.Risk, ScopeTarget.Instance,
            subjectId: policy.Id, subjectKind: nameof(RiskPolicy),
            detail: $"{policy.Name}: {config.Categories.Count(c => c.Value.Enabled)} categories enabled, "
                  + $"basis {RiskScorer.WeightBasis(config):0.#}");

        await _db.SaveChangesAsync(ct);
        return Result<Guid>.Ok(policy.Id);
    }

    /// <summary>
    /// Duplicate. How an Architect changes weights without editing in place,
    /// and the only way to modify a system policy's shape.
    /// </summary>
    public async Task<Result<Guid>> DuplicateAsync(
        Principal actor, Guid policyId, string newName, CancellationToken ct = default)
    {
        var decision = _capabilities.Evaluate(actor, Capability.DuplicatePolicy);
        if (!decision.Allowed) return Result<Guid>.Denied(decision.Reason!);

        var source = await _db.RiskPolicies.AsNoTracking().SingleOrDefaultAsync(p => p.Id == policyId, ct);
        if (source is null) return Result<Guid>.Invalid("That policy no longer exists.");

        newName = newName.Trim();
        if (newName.Length == 0) return Result<Guid>.Invalid("The copy needs a name.");

        var clash = await _db.RiskPolicies.AnyAsync(p => p.Name.ToLower() == newName.ToLower(), ct);
        if (clash) return Result<Guid>.Invalid($"A policy called \"{newName}\" already exists.");

        var copy = new RiskPolicy
        {
            Name = newName,
            Description = source.Description,
            // A copy is never the default and never seeded, whatever its
            // source was. Inheriting either would silently move every project
            // that has no explicit policy onto an untested one.
            IsDefault = false,
            IsSeeded = false,
            Config = Clone(source.Config),
            CreatedByUserId = actor.UserId,
        };
        _db.RiskPolicies.Add(copy);

        _audit.Record(actor, "policy.duplicated", AuditClass.Other, ScopeTarget.Instance,
            subjectId: copy.Id, subjectKind: nameof(RiskPolicy),
            detail: $"{newName} from {source.Name}");

        await _db.SaveChangesAsync(ct);
        return Result<Guid>.Ok(copy.Id);
    }

    /// <summary>
    /// Delete, refused while anything points at the policy.
    ///
    /// Cascading would silently move projects onto the default policy and
    /// change their scores with no record of why. The dialog offers to move
    /// them explicitly instead.
    /// </summary>
    public async Task<Result<bool>> DeleteAsync(
        Principal actor, Guid policyId, Guid? moveTo = null, CancellationToken ct = default)
    {
        var decision = _capabilities.Evaluate(actor, Capability.EditPolicyWeights);
        if (!decision.Allowed) return Result<bool>.Denied(decision.Reason!);

        var policy = await _db.RiskPolicies.SingleOrDefaultAsync(p => p.Id == policyId, ct);
        if (policy is null) return Result<bool>.Ok(false);

        if (policy.IsDefault)
            return Result<bool>.Invalid(
                "This is the instance default. Make another policy the default first — otherwise a "
                + "project with no explicit policy would have nothing to score against.");

        var projects = await _db.Projects.Where(p => p.RiskPolicyId == policyId).ToListAsync(ct);
        var clients = await _db.Clients.Where(c => c.RiskPolicyId == policyId).ToListAsync(ct);
        var users = projects.Count + clients.Count;

        if (users > 0)
        {
            if (moveTo is not { } target)
            {
                return Result<bool>.Invalid(
                    $"{users} project{(users == 1 ? "" : "s")} and client{(clients.Count == 1 ? "" : "s")} "
                    + "still use this policy. Choose where to move them first — deleting it silently "
                    + "would change their scores with no record of why.");
            }

            if (!await _db.RiskPolicies.AnyAsync(p => p.Id == target, ct))
                return Result<bool>.Invalid("The policy to move to no longer exists.");

            foreach (var project in projects) project.RiskPolicyId = target;
            foreach (var client in clients) client.RiskPolicyId = target;
        }

        _db.RiskPolicies.Remove(policy);

        _audit.Record(actor, "policy.deleted", AuditClass.Risk, ScopeTarget.Instance,
            subjectId: policy.Id, subjectKind: nameof(RiskPolicy),
            detail: users > 0
                ? $"{policy.Name}; moved {users} assignment{(users == 1 ? "" : "s")} to {moveTo}"
                : policy.Name);

        await _db.SaveChangesAsync(ct);
        return Result<bool>.Ok(true);
    }

    /// <summary>
    /// What the projects using this policy would score under a proposed config,
    /// WITHOUT saving it.
    ///
    /// This is the point of the editor. A weight change is abstract until
    /// someone can see which projects move band because of it.
    /// </summary>
    public async Task<IReadOnlyList<RescoreRow>> PreviewAsync(
        Guid policyId, RiskPolicyConfig proposed, CancellationToken ct = default)
    {
        var current = await _db.RiskPolicies.AsNoTracking()
            .SingleOrDefaultAsync(p => p.Id == policyId, ct);
        if (current is null) return [];

        var projects = await _db.Projects.AsNoTracking()
            .Where(p => p.RiskPolicyId == policyId
                     || (p.RiskPolicyId == null && p.Client!.RiskPolicyId == policyId))
            .Select(p => new { p.Id, p.Name })
            .ToArrayAsync(ct);

        var rows = new List<RescoreRow>(projects.Length);
        foreach (var project in projects)
        {
            // The latest canonical build, matching what the hub scores. A
            // preview against a pull-request build would move a number nobody
            // is looking at.
            var build = await _db.ComponentVersions.AsNoTracking()
                .Where(v => v.Component!.ProjectId == project.Id
                         && v.PullRequestRef == null
                         && (v.BranchName == null || v.BranchName == "main" || v.BranchName == "master"))
                .OrderByDescending(v => v.CreatedAt)
                .Select(v => new { v.Id, v.CommitSha, v.VersionString })
                .ToArrayAsync(ct);

            if (build.Length == 0)
            {
                // A project with no build has no score to move. Saying so beats
                // showing it at 0.0, which would read as a measured result.
                rows.Add(new RescoreRow(project.Id, project.Name, null, null, null, null));
                continue;
            }

            var top = build[0].CommitSha ?? build[0].VersionString;
            var ids = build.Where(b => (b.CommitSha ?? b.VersionString) == top).Select(b => b.Id).ToList();

            var inputs = await _inputs.BuildAsync(ids, current.Config, project.Id, ct);
            var before = RiskScorer.Compute(current.Config, inputs);
            // Same inputs, both configs. Rebuilding inputs per config would let
            // an unrelated ingest between the two calls masquerade as an effect
            // of the weight change.
            var after = RiskScorer.Compute(proposed, inputs);

            rows.Add(new RescoreRow(
                project.Id, project.Name,
                Math.Round(before.Score, 1), before.Band,
                Math.Round(after.Score, 1), after.Band));
        }

        return rows
            // Band changes first — those are the ones that alter whether a
            // build ships, and the rest are just numbers moving.
            .OrderByDescending(r => r.BandChanged)
            .ThenByDescending(r => Math.Abs((r.After ?? 0) - (r.Before ?? 0)))
            .ThenBy(r => r.ProjectName, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static string? Validate(RiskPolicyConfig config)
    {
        if (config.SchemaVersion is < 1 or > RiskScorer.MaxSupportedSchemaVersion)
            return $"Schema version {config.SchemaVersion} is not one the scorer understands.";

        if (config.Categories.Values.Any(c => c.Max < 0))
            return "A category weight cannot be negative.";

        if (!config.Categories.Values.Any(c => c.Enabled && c.Max > 0))
            return "At least one category has to be enabled with a weight, or every project scores 0 "
                 + "and a zero nobody measured reads like a clean result.";

        var b = config.Bands;
        if (b.GreenMax <= 0 || b.GreenMax >= b.YellowMax || b.YellowMax >= b.OrangeMax || b.OrangeMax >= 100)
            return "Band boundaries must ascend: 0 < green < yellow < orange < 100.";

        return null;
    }

    // Round-tripped through JSON rather than hand-copied: the config is a
    // nested mutable graph, and a shallow copy would let the editor's pending
    // edits reach the tracked entity.
    private static RiskPolicyConfig Clone(RiskPolicyConfig config) =>
        JsonSerializer.Deserialize<RiskPolicyConfig>(JsonSerializer.Serialize(config))!;
}

public sealed record PolicyCard(
    Guid Id, string Name, string? Description, bool IsDefault, bool IsSeeded,
    int SchemaVersion, int EnabledCategories, int ProjectCount, int ClientCount,
    DateTimeOffset UpdatedAt)
{
    public int UseCount => ProjectCount + ClientCount;
}

public sealed record PolicyDetail(
    Guid Id, string Name, string? Description, bool IsDefault, bool IsSeeded, RiskPolicyConfig Config);

public sealed record RescoreRow(
    Guid ProjectId, string ProjectName,
    double? Before, string? BeforeBand,
    double? After, string? AfterBand)
{
    /// <summary>
    /// The change that actually matters. A score moving 3 points inside a band
    /// changes nothing; a score crossing into orange can stop a release.
    /// </summary>
    public bool BandChanged => BeforeBand is not null && AfterBand is not null && BeforeBand != AfterBand;
}
