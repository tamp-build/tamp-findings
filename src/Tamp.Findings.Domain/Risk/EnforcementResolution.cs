using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Domain.Risk;

// The effective enforcement mode for a build (ADR 0004; TFND-148 / TFND-149).
//
// Resolution follows the same chain as risk policy — Project → Client →
// Instance, most-specific wins — with one exception: when the instance default
// is LOCKED, the instance mode becomes a floor, and the resolved project/client
// setting may only match or exceed it, never weaken it.
//
// Pure and deterministic (no I/O), like GateEvaluator, so a verdict recorded in
// an attestation can be reproduced later.
public static class EnforcementResolution
{
    /// <summary>
    /// Effective mode given the instance floor/lock and the optional client and
    /// project overrides. Nulls mean "inherit".
    /// </summary>
    public static EnforcementMode Resolve(
        EnforcementMode instanceMode,
        bool instanceLocked,
        EnforcementMode? clientMode,
        EnforcementMode? projectMode)
    {
        // Most-specific wins: project, else client, else the instance default.
        var requested = projectMode ?? clientMode ?? instanceMode;

        // Unlocked: the resolved setting stands. Locked: the instance mode is a
        // floor — take the stricter of the two (Enforcing > Advisory).
        return instanceLocked
            ? (EnforcementMode)Math.Max((int)instanceMode, (int)requested)
            : requested;
    }
}
