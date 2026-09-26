using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Domain.Risk;

// The fail-closed exit decision for the CLI gate (ADR 0004 §4.5).
//
// Pure and shared with the CLI so the decision table has exactly one
// implementation. Advisory never fails the build; enforcing fails on anything
// that is not a definitive Pass — including "could not reach a verdict", which
// is the whole point of a hard gate in an air-gapped enclave.
public enum GateOutcome
{
    Pass,        // Clear to ship — nothing blocks.
    Fail,        // At least one blocking Fail gate. Remedy: fix the finding.
    Unknown,     // Blocking, no Fail, a gate could not be evaluated (scanner never ran).
    Error,       // Blocking, no Fail, evaluation itself broke.
    Unreachable, // No verdict at all: timeout, auth failure, no build record, server down.
}

public static class GateExit
{
    // Distinct codes so a human or an agent can tell "scanner didn't run" from
    // "server was down"; CI only needs non-zero to fail the step.
    public const int Ok = 0;
    public const int Fail = 10;
    public const int Unknown = 11;
    public const int Error = 12;
    public const int Unreachable = 20;

    /// <summary>The process exit code for an outcome under a resolved mode.</summary>
    public static int CodeFor(GateOutcome outcome, EnforcementMode mode)
    {
        // Advisory never fails the build — the caller opted into non-blocking,
        // even for a broken setup. It still reports loudly elsewhere.
        if (mode == EnforcementMode.Advisory) return Ok;

        return outcome switch
        {
            GateOutcome.Pass => Ok,
            GateOutcome.Fail => Fail,
            GateOutcome.Unknown => Unknown,
            GateOutcome.Error => Error,
            GateOutcome.Unreachable => Unreachable,
            _ => Unreachable,
        };
    }

    /// <summary>
    /// The ship outcome from the enabled gates' verdicts. Pass only when nothing
    /// blocks; otherwise Fail outranks Error outranks Unknown (all block, but the
    /// most actionable remedy is reported).
    /// </summary>
    public static GateOutcome OutcomeFrom(IEnumerable<GateVerdict> verdicts)
    {
        var blocks = false;
        var fail = false;
        var error = false;
        var unknown = false;

        foreach (var v in verdicts)
        {
            if (v == GateVerdict.Pass) continue;
            blocks = true;
            switch (v)
            {
                case GateVerdict.Fail: fail = true; break;
                case GateVerdict.Error: error = true; break;
                case GateVerdict.Unknown: unknown = true; break;
            }
        }

        if (!blocks) return GateOutcome.Pass;
        if (fail) return GateOutcome.Fail;
        if (error) return GateOutcome.Error;
        if (unknown) return GateOutcome.Unknown;
        return GateOutcome.Pass;
    }
}
