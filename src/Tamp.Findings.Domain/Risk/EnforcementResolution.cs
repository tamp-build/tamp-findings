using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Domain.Risk;

// The effective enforcement mode for a build (ADR 0004; TFND-148 / TFND-149,
// corrected by TFND-247).
//
// ONE rule: the authored mode is the STRICTEST across the policy layers
// (template → client → archetype → project), and the instance mode is a floor
// when the deployment locks it. Nothing below can weaken anything above.
//
// It used to be two rules that disagreed, which is what TFND-247 was.
// `PolicyLayerMerge` already computed a strictest-wins Mode with provenance —
// exactly what ADR 0007's table promised — and then this function ignored it,
// resolving `projectMode ?? clientMode ?? instanceMode` most-specific-wins
// instead. So a client set to Enforcing was weakened by a project set to
// Advisory, which ADR 0007 said was impossible.
//
// Worse, in practice the client arm was dead: the caller read the legacy
// `Client.EnforcementMode` scalar, which nothing has written since the policy
// layers landed, so a client-level mode authored through the only UI that
// writes it had NO effect on enforcement at all. The merged Mode is now the
// input, so authored intent takes effect and the two ADRs describe one
// behaviour.
//
// Pure and deterministic (no I/O), like GateEvaluator, so a verdict recorded in
// an attestation can be reproduced later.
public static class EnforcementResolution
{
    /// <summary>
    /// Effective mode, given the instance default and whether the deployment
    /// locks it, plus the mode authored across the policy layers.
    /// </summary>
    /// <param name="authoredMode">
    /// The strictest mode across template → client → archetype → project, as
    /// <c>PolicyLayerMerge</c> resolves it. Null means no layer set one, in
    /// which case the instance default stands.
    ///
    /// A single parameter rather than one per layer, because the merge has
    /// already collapsed them and taking them separately here is what let this
    /// function apply a different precedence than the merge did.
    /// </param>
    public static EnforcementMode Resolve(
        EnforcementMode instanceMode,
        bool instanceLocked,
        EnforcementMode? authoredMode)
    {
        var requested = authoredMode ?? instanceMode;

        // Unlocked: the authored mode stands — it is already the strictest any
        // layer asked for. Locked: the instance mode is a floor the layers may
        // meet or exceed and never undercut.
        return instanceLocked
            ? (EnforcementMode)Math.Max((int)instanceMode, (int)requested)
            : requested;
    }
}
