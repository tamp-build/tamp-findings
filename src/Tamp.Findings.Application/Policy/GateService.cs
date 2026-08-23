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
/// Editing gates changes the release contract. It needs
/// <see cref="Capability.EditGates"/> — Admin and InfoSec only — and it is
/// audited as a risk decision, because loosening a gate is indistinguishable in
/// its effect from fixing the thing the gate was catching.
/// </summary>
public sealed class GateService
{
    private readonly FindingsDbContext _db;
    private readonly CapabilityEvaluator _capabilities;
    private readonly AuditLog _audit;

    public GateService(FindingsDbContext db, CapabilityEvaluator capabilities, AuditLog audit)
    {
        _db = db;
        _capabilities = capabilities;
        _audit = audit;
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

    public async Task<Result<int>> SaveAsync(
        Principal actor, ScopeTarget scope, Guid projectId, IReadOnlyList<GateRow> gates,
        CancellationToken ct = default)
    {
        var decision = _capabilities.Evaluate(actor, Capability.EditGates);
        if (!decision.Allowed) return Result<int>.Denied(decision.Reason!);

        var project = await _db.Projects.SingleOrDefaultAsync(p => p.Id == projectId, ct);
        if (project is null) return Result<int>.Invalid("That project no longer exists.");

        foreach (var gate in gates.Where(g => g.Enabled && g.Threshold is < 0))
            return Result<int>.Invalid($"{gate.Label} cannot have a negative threshold.");

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

        // The audit detail names what CHANGED, not the whole config. An
        // assessor asking "when did criticalDast get turned off?" should be
        // able to read the answer, not diff two blobs.
        var changes = Describe(before, after);

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

    private static List<string> Describe(ProjectGatesConfig before, ProjectGatesConfig after)
    {
        var changes = new List<string>();

        foreach (var (key, now) in after.Gates)
        {
            before.Gates.TryGetValue(key, out var was);
            var wasEnabled = was?.Enabled ?? false;

            if (wasEnabled != now.Enabled)
                changes.Add($"{key} {(now.Enabled ? "enabled" : "DISABLED")}");
            else if (now.Enabled && was?.Threshold != now.Threshold)
                changes.Add($"{key} threshold {Show(was?.Threshold)} → {Show(now.Threshold)}");
        }

        return changes;
    }

    private static string Show(double? value) => value?.ToString("0.##") ?? "default";

    /// <summary>
    /// Whether a threshold means anything for this gate. A boolean gate with an
    /// editable threshold invites someone to set one and believe it did
    /// something.
    /// </summary>
    public static bool TakesThreshold(string key) => key is
        GateKeys.RiskScoreRegression or
        GateKeys.CoverageRegression or
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
