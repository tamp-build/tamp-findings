using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Application.Auditing;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Projects;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Risk;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Application.Policy;

/// <summary>
/// The acceptance gates for one project (TFND-106).
///
/// Gates are PER PROJECT while the risk policy is instance-wide, because the
/// same definition of "bad" can back very different shipping rules: a pilot and
/// a production service score identically and ship on different terms.
///
/// Editing gates changes the release contract. <see cref="SaveAsync"/> needs
/// <see cref="Capability.EditGates"/> — Admin and InfoSec only — and it is
/// audited as a risk decision, because loosening a gate is indistinguishable in
/// its effect from fixing the thing the gate was catching.
///
/// <see cref="HardenAsync"/> is the narrower operation (TFND-252): one gate,
/// tightened, and it verifies the direction itself rather than trusting the
/// caller. It needs only <see cref="Capability.HardenGates"/>, which Architect
/// also holds and an agent token can carry, because a tightening cannot loosen
/// the release contract — it fails loudly, blocks something, and gets reverted
/// by whoever it inconvenienced. That asymmetry is why the two operations have
/// different capabilities instead of one with a flag.
/// </summary>
public sealed class GateService
{
    private readonly FindingsDbContext _db;
    private readonly CapabilityEvaluator _capabilities;
    private readonly AuditLog _audit;
    private readonly PolicyResolver _resolver;

    public GateService(
        FindingsDbContext db, CapabilityEvaluator capabilities, AuditLog audit, PolicyResolver resolver)
    {
        _db = db;
        _capabilities = capabilities;
        _audit = audit;
        _resolver = resolver;
    }

    /// <summary>
    /// Every well-known gate with this project's setting, including the ones it
    /// has never configured.
    ///
    /// Deriving the list from stored config would mean a gate nobody has
    /// enabled yet is a gate nobody can enable.
    /// </summary>
    public async Task<IReadOnlyList<GateRow>> ListAsync(Guid projectId, CancellationToken ct = default)
    {
        var config = await _db.Projects.AsNoTracking()
            .Where(p => p.Id == projectId)
            .Select(p => p.GatesConfig)
            .SingleOrDefaultAsync(ct) ?? ProjectGatesDefaults.Empty();

        return GateEvaluator.WellKnownGateKeys
            .Select(key =>
            {
                config.Gates.TryGetValue(key, out var gate);
                return new GateRow(
                    key,
                    GateEvaluator.Label(key),
                    GateEvaluator.Describe(key),
                    gate?.Enabled ?? false,
                    gate?.Threshold,
                    TakesThreshold(key));
            })
            .ToArray();
    }

    /// <summary>This project's enforcement-mode override, or null when it inherits.</summary>
    public async Task<EnforcementMode?> EnforcementOverrideAsync(Guid projectId, CancellationToken ct = default) =>
        (await _db.Projects.AsNoTracking()
            .Where(p => p.Id == projectId)
            .Select(p => p.GatesConfig)
            .SingleOrDefaultAsync(ct))?.EnforcementMode;

    public async Task<Result<int>> SaveAsync(
        Principal actor, ScopeTarget scope, Guid projectId, IReadOnlyList<GateRow> gates,
        EnforcementMode? enforcementMode = null,
        CancellationToken ct = default)
    {
        var decision = _capabilities.Evaluate(actor, Capability.EditGates);
        if (!decision.Allowed) return Result<int>.Denied(decision.Reason!);

        var project = await _db.Projects.SingleOrDefaultAsync(p => p.Id == projectId, ct);
        if (project is null) return Result<int>.Invalid("That project no longer exists.");

        if (gates.FirstOrDefault(g => g.Enabled && g.Threshold is < 0) is { } negative)
            return Result<int>.Invalid($"{negative.Label} cannot have a negative threshold.");

        var before = project.GatesConfig ?? ProjectGatesDefaults.Empty();
        var after = new ProjectGatesConfig { SchemaVersion = before.SchemaVersion };

        foreach (var gate in gates)
        {
            // Disabled gates are still stored rather than dropped: a threshold
            // someone tuned before switching the gate off should still be there
            // when they switch it back on.
            after.Gates[gate.Key] = new GateConfig
            {
                Enabled = gate.Enabled,
                Threshold = TakesThreshold(gate.Key) ? gate.Threshold : null,
            };
        }

        // Per-project enforcement override (TFND-148). Null → inherit
        // (Client → Instance). A locked instance floor still wins at evaluation
        // time (EnforcementResolution), so storing advisory here is honest even
        // when it will be overridden upward.
        after.EnforcementMode = enforcementMode;

        // The audit detail names what CHANGED, not the whole config. An
        // assessor asking "when did criticalDast get turned off?" should be
        // able to read the answer, not diff two blobs.
        var changes = Describe(before, after);
        if (before.EnforcementMode != after.EnforcementMode)
            changes.Add($"enforcement {after.EnforcementMode?.ToString().ToLowerInvariant() ?? "inherit"}");

        // A no-op save writes no audit entry. An entry that says nothing
        // changed dilutes the log an assessor reads first.
        if (changes.Count == 0) return Result<int>.Ok(0);

        project.GatesConfig = after;

        _audit.Record(actor, AuditActions.GateChanged, AuditClass.Risk, scope,
            subjectId: project.Id, subjectKind: "ProjectGates",
            detail: string.Join("; ", changes));

        await _db.SaveChangesAsync(ct);
        return Result<int>.Ok(changes.Count);
    }

/// <summary>
    /// Tighten one gate: enable it, or lower its threshold (TFND-252).
    ///
    /// Verifies the direction HERE rather than trusting the caller, because the
    /// capability it accepts is deliberately wider than
    /// <see cref="Capability.EditGates"/> and the thing keeping that safe is
    /// this check. A caller holding HardenGates and nothing else must not be
    /// able to reach a loosening write through a method named for hardening.
    ///
    /// Compared against the RESOLVED value — what the template, client and
    /// archetype already impose — not against the project's own stored row. A
    /// write that is stricter than the project's own setting but looser than
    /// what it inherits would change nothing, and reporting it as a tightening
    /// would be a false statement about the release contract.
    ///
    /// Note what this does NOT touch: enforcement mode. Raising it is a posture
    /// decision with a blast radius past one gate, and lowering it is the
    /// weakening this method exists to refuse.
    /// </summary>
    public async Task<Result<bool>> HardenAsync(
        Principal actor, ScopeTarget scope, Guid projectId, string gateKey, double? threshold,
        CancellationToken ct = default)
    {
        var decision = _capabilities.Evaluate(actor, Capability.HardenGates);
        if (!decision.Allowed) return Result<bool>.Denied(decision.Reason!);

        if (!GateEvaluator.WellKnownGateKeys.Contains(gateKey))
            return Result<bool>.Invalid($"'{gateKey}' is not a gate this instance knows.");

        var takesThreshold = TakesThreshold(gateKey);
        if (!takesThreshold && threshold is not null)
            return Result<bool>.Invalid($"{GateEvaluator.Label(gateKey)} has no threshold.");

        if (threshold is < 0)
            return Result<bool>.Invalid("A threshold cannot be negative.");

        var project = await _db.Projects.SingleOrDefaultAsync(p => p.Id == projectId, ct);
        if (project is null) return Result<bool>.Invalid("That project no longer exists.");

        var resolved = await _resolver.ForProjectAsync(projectId, ct);
        resolved.Gates.TryGetValue(gateKey, out var inForce);

        // Already strictly covered: enabling adds nothing, and a threshold that
        // is not lower adds nothing either.
        if (inForce is { Enabled: true })
        {
            if (!takesThreshold)
                return Result<bool>.Ok(false);

            if (threshold is null)
                return Result<bool>.Ok(false);

            if (inForce.Threshold is { } current && threshold >= current)
            {
                return Result<bool>.Invalid(
                    $"{inForce.Source} already imposes {current} on {GateEvaluator.Label(gateKey)}; "
                    + $"{threshold} is not stricter and would have no effect.");
            }
        }

        var before = project.GatesConfig ?? ProjectGatesDefaults.Empty();
        var after = new ProjectGatesConfig
        {
            SchemaVersion = before.SchemaVersion,
            EnforcementMode = before.EnforcementMode,
        };
        foreach (var (key, cfg) in before.Gates)
            after.Gates[key] = new GateConfig { Enabled = cfg.Enabled, Threshold = cfg.Threshold };

        after.Gates[gateKey] = new GateConfig
        {
            Enabled = true,
            Threshold = takesThreshold ? threshold : null,
        };

        var changes = Describe(before, after);
        if (changes.Count == 0) return Result<bool>.Ok(false);

        project.GatesConfig = after;

        _audit.Record(actor, AuditActions.GateChanged, AuditClass.Risk, scope,
            subjectId: project.Id, subjectKind: "ProjectGates",
            // Says it was a hardening, so a reader can tell this entry from an
            // ordinary gate edit without diffing two configs.
            detail: "hardened: " + string.Join("; ", changes));

        await _db.SaveChangesAsync(ct);
        return Result<bool>.Ok(true);
    }

    private static List<string> Describe(ProjectGatesConfig before, ProjectGatesConfig after)
    {
        var changes = new List<string>();

        foreach (var (key, now) in after.Gates)
        {
            before.Gates.TryGetValue(key, out var was);
            var wasEnabled = was?.Enabled ?? false;

            if (wasEnabled != now.Enabled)
                changes.Add($"{key} {(now.Enabled ? "enabled" : "DISABLED")}");
            else if (now.Enabled && ThresholdChanged(was?.Threshold, now.Threshold))
                changes.Add($"{key} threshold {Show(was?.Threshold)} → {Show(now.Threshold)}");
        }

        return changes;
    }

    // Thresholds are doubles, so compare with a tolerance rather than exact (in)equality.
    private static bool ThresholdChanged(double? before, double? after) =>
        before.HasValue != after.HasValue || (before.HasValue && Math.Abs(before.Value - after!.Value) > 1e-9);

    private static string Show(double? value) => value?.ToString("0.##") ?? "default";

    /// <summary>
    /// Whether a threshold means anything for this gate. A boolean gate with an
    /// editable threshold invites someone to set one and believe it did
    /// something.
    /// </summary>
    public static bool TakesThreshold(string key) => key is
        GateKeys.RiskScoreRegression or
        GateKeys.CoverageRegression or
        GateKeys.CoverageFloor or
        GateKeys.SbomAge or
        GateKeys.BaseImageAge or
        GateKeys.AnyCves or
        GateKeys.CriticalCves or
        GateKeys.HighCves or
        GateKeys.CriticalSast or
        GateKeys.HighSast or
        GateKeys.CriticalDast or
        GateKeys.HighDast or
        GateKeys.CriticalIac or
        GateKeys.TestFailures or
        GateKeys.PoamPastDue;
}

public sealed record GateRow(
    string Key, string Label, string Description, bool Enabled, double? Threshold, bool HasThreshold)
{
    // Mutable copies for the editor to bind against, without letting a
    // half-edited row reach the stored config.
    public GateRow With(bool enabled) => this with { Enabled = enabled };
    public GateRow With(double? threshold) => this with { Threshold = threshold };
}
