using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Domain.Compliance;

// The point-in-time engine (ADR 0011 §4, §7), pure and deterministic like
// GateEvaluator and PolicyLayerMerge. A directive's status as of any date is the
// latest append-only status change on or before that date. This is what lets a
// compliance claim be evaluated against the mandate set in force *then*, and what
// makes a rescind forward-dated rather than retroactive.
public static class DirectiveStatusResolver
{
    /// <summary>
    /// The directive's status as of <paramref name="asOf"/>: the latest status change
    /// with EffectiveDate ≤ asOf. Null when the directive did not yet exist as of that
    /// date (no change on or before it) — it was not in force, and was not a finding.
    /// </summary>
    public static DirectiveStatus? StatusAsOf(
        IEnumerable<DirectiveStatusChange> changes, DateTimeOffset asOf)
    {
        DirectiveStatusChange? winner = null;
        foreach (var c in changes)
        {
            if (c.EffectiveDate > asOf) continue;
            // Latest effective date wins; ties break on the later RecordedAt so a
            // correction recorded later supersedes the one it corrects.
            if (winner is null
                || c.EffectiveDate > winner.EffectiveDate
                || (c.EffectiveDate == winner.EffectiveDate && c.RecordedAt > winner.RecordedAt))
                winner = c;
        }
        return winner?.Status;
    }

    /// <summary>A directive is IN FORCE as of a date when its status then is Active.
    /// Rescinded/Superseded/absent are not in force — a since-rescinded directive stops
    /// accruing findings after its rescind date, without erasing history before it.</summary>
    public static bool IsInForceAsOf(
        IEnumerable<DirectiveStatusChange> changes, DateTimeOffset asOf)
        => StatusAsOf(changes, asOf) == DirectiveStatus.Active;
}
