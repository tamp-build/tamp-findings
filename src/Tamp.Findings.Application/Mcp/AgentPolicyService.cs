using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Application.Policy;
using Tamp.Findings.Application.Risk;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Risk;

namespace Tamp.Findings.Application.Mcp;

/// <summary>
/// Policy edits an agent may perform (TFND-252).
///
/// Four gates, each answering a different question, and all four must pass.
///
/// ZERO — the operator has to have asked for this. The instance setting
/// <c>AgentPolicyAuthoring</c> is off by default. Some deployments want an agent
/// that helps configure the thing; others want policy to be a human act. The
/// product does not decide that for them, and the default is the cautious one.
///
/// ONE — closed when the deployment pins enforcement. <see cref="InstanceEnforcementPolicy.ConfigLocked"/>
/// comes from configuration rather than the database precisely so a platform
/// team can mandate a posture an in-app admin cannot lower (ADR 0004 §3.3).
/// Policy editing through the agent surface is closed while it holds. Note the
/// direction, because the opposite reading is tempting: locked CLOSES editing,
/// it does not permit it. Reads stay open regardless.
///
/// TWO — hardening only, and no setting changes that. Even with authoring
/// enabled an agent may tighten a threshold or enable a gate; it may not loosen
/// one or turn one off. ADR 0019 §5 is a property, not a dial, so no
/// configuration can hand a credential the moves that make a build easier to
/// ship. This lives HERE and not in
/// <see cref="GateService"/>, and the distinction took a wrong turn to find
/// (TFND-247): <see cref="PolicyLayerMerge"/> already prevents a project
/// weakening what it inherits, and where nothing is inherited a human loosening
/// their own project's gate is a legitimate decision the service should keep
/// allowing. What must not happen is an AGENT moving a verdict in the permissive
/// direction (ADR 0019 §5). That is a property of this surface, not of the
/// policy model.
///
/// THREE — the blocking layer only. Gates and thresholds, never the scoring
/// policy. ADR 0007 §2 leaves weights, caps and bands outside the harden-only
/// model because hardening is not well-defined for a weight, so there is no
/// structural guarantee an agent editing scoring cannot lower a score — and a
/// tool with no safety property behind it is not one worth having.
/// </summary>
public sealed class AgentPolicyService
{
    private readonly FindingsDbContext _db;
    private readonly AgentScope _scope;
    private readonly GateService _gates;
    private readonly PolicyResolver _policy;
    private readonly InstanceEnforcementPolicy _lock;
    private readonly Projects.ProjectSettingsService _settings;

    public AgentPolicyService(
        FindingsDbContext db,
        AgentScope scope,
        GateService gates,
        PolicyResolver policy,
        InstanceEnforcementPolicy enforcementLock,
        Projects.ProjectSettingsService settings)
    {
        _db = db;
        _scope = scope;
        _gates = gates;
        _policy = policy;
        _lock = enforcementLock;
        _settings = settings;
    }

    /// <summary>
    /// Harden one gate on a project: enable it, or lower its threshold.
    ///
    /// Refuses, with its reason, any of: a locked deployment, a project outside
    /// scope, a missing capability, a loosening, or a change that would be a
    /// no-op because an upper layer already imposes something stricter.
    ///
    /// That last refusal is not safety, it is honesty. A write the merge
    /// discards leaves the agent reporting "I tightened the gate" about an
    /// evidence record that did not change, and a false statement about the
    /// record is the failure mode this product exists to prevent.
    /// </summary>
    public async Task<AgentPolicyEditResult> HardenGateAsync(
        AgentIdentity agent, Guid projectId, string gateKey, bool enabled, double? threshold,
        CancellationToken ct = default)
    {
        if (!await _settings.AgentPolicyAuthoringAsync(ct))
        {
            return AgentPolicyEditResult.Refused(
                "This instance does not let agents author policy. An administrator can turn it on "
                + "under System > Instance settings; it is off by default because policy is a "
                + "human act unless somebody decides otherwise. Report the change you would make "
                + "and let a person apply it.");
        }

        if (_lock.ConfigLocked)
        {
            return AgentPolicyEditResult.Refused(
                "This deployment pins enforcement by configuration, so policy is not editable "
                + "through the agent surface. The lock is a platform-team decision and is not "
                + "something to work around — report the intended change to a person instead.");
        }

        if (!await _scope.ReachesAsync(agent, projectId, ct))
            return AgentPolicyEditResult.Refused("That project is outside this token's scope.");

        // HardenGates, not EditGates (TFND-252). EditGates means "edit freely,
        // including loosen" and is Admin/InfoSec only — neither of which an
        // agent can be. Hardening is its own capability precisely so it can be
        // granted to a role an agent may carry without widening what that role
        // may loosen.
        if (_scope.Denied(agent, Authorization.Capability.HardenGates) is { } denied)
        {
            return AgentPolicyEditResult.Refused(
                denied + " Tightening a gate needs HardenGates, which an agent token carries only "
                + "when it was minted as Architect.");
        }

        if (!GateEvaluator.WellKnownGateKeys.Contains(gateKey))
        {
            return AgentPolicyEditResult.Refused(
                $"'{gateKey}' is not a gate this instance knows. Read get_policy for the keys; a "
                + "gate invented here would be stored and silently ignored by the evaluator.");
        }

        var takesThreshold = GateService.TakesThreshold(gateKey);
        if (!takesThreshold && threshold is not null)
        {
            return AgentPolicyEditResult.Refused(
                $"{GateEvaluator.Label(gateKey)} is a boolean gate and has no threshold. Passing "
                + "one would be stored and ignored, which reads later as a setting that exists.");
        }

        if (takesThreshold && threshold is < 0)
            return AgentPolicyEditResult.Refused("A threshold cannot be negative.");

        // An agent may not turn a gate off. Stated before the comparison below
        // because it is the clearest case and deserves its own sentence.
        if (!enabled)
        {
            return AgentPolicyEditResult.Refused(
                "An agent cannot disable a gate. Hardening only: this surface may make a build "
                + "harder to ship and never easier (ADR 0019 §5). Disabling a gate is a decision "
                + "for a person.");
        }

        var project = await _db.Projects.FirstOrDefaultAsync(p => p.Id == projectId, ct);
        if (project is null) return AgentPolicyEditResult.Refused("That project no longer exists.");

        // What is in force now, and which layer imposed it.
        var merged = await _policy.ForProjectAsync(projectId, ct);
        merged.Gates.TryGetValue(gateKey, out var current);

        if (current is { Enabled: true })
        {
            // Already on. The only remaining hardening is a lower threshold.
            if (!takesThreshold)
            {
                return AgentPolicyEditResult.NoChange(
                    $"{GateEvaluator.Label(gateKey)} is already enabled by {current.Source}, and it "
                    + "has no threshold to tighten. Nothing to do.");
            }

            if (threshold is null)
            {
                return AgentPolicyEditResult.NoChange(
                    $"{GateEvaluator.Label(gateKey)} is already enabled by {current.Source}. "
                    + "Pass a lower threshold to tighten it.");
            }

            if (current.Threshold is { } inForce && threshold >= inForce)
            {
                return AgentPolicyEditResult.Refused(
                    $"{current.Source} already imposes a threshold of {inForce} on "
                    + $"{GateEvaluator.Label(gateKey)}. {threshold} is not stricter, and writing it "
                    + "into this project's layer would change nothing — the merge takes the lower "
                    + "value. Do not report this as a tightening.");
            }
        }

        // Delegate the write to GateService.HardenAsync, which owns the
        // direction check and the audit entry. Not SaveAsync: that takes a whole
        // config and needs EditGates, which an agent cannot hold — and a method
        // that replaces every gate at once is the wrong shape for a caller
        // allowed to change exactly one in exactly one direction.
        var saved = await _gates.HardenAsync(
            agent.Principal,
            Authorization.ScopeTarget.Project(project.ClientId, projectId),
            projectId,
            gateKey,
            takesThreshold ? threshold : null,
            ct);

        if (!saved.Success)
            return AgentPolicyEditResult.Refused(saved.Error ?? "The gate could not be saved.");

        if (!saved.Value)
            return AgentPolicyEditResult.NoChange("That is already this project's setting.");

        var after = await _policy.ForProjectAsync(projectId, ct);
        after.Gates.TryGetValue(gateKey, out var now);

        return AgentPolicyEditResult.Hardened(
            gateKey, GateEvaluator.Label(gateKey), now?.Enabled ?? true, now?.Threshold, now?.Source);
    }
}

/// <summary>
/// The outcome of an attempted policy edit (TFND-252).
///
/// Three outcomes rather than two, because "refused" and "nothing needed doing"
/// are different facts and an agent told the wrong one will either retry
/// pointlessly or report a change it did not make.
/// </summary>
public sealed record AgentPolicyEditResult(
    bool Changed,
    string? GateKey,
    string? Label,
    bool? Enabled,
    double? Threshold,
    string? Source,
    string? Refusal,
    string? NoChangeReason)
{
    public static AgentPolicyEditResult Hardened(
        string key, string label, bool enabled, double? threshold, string? source) =>
        new(true, key, label, enabled, threshold, source, null, null);

    public static AgentPolicyEditResult Refused(string reason) =>
        new(false, null, null, null, null, null, reason, null);

    public static AgentPolicyEditResult NoChange(string reason) =>
        new(false, null, null, null, null, null, null, reason);
}
