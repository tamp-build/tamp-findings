using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Application.Authorization;

/// <summary>
/// Conflicting role combinations.
///
/// <para>
/// Flagged, not blocked, by default. The hand-off is explicit about why: "The
/// flag is recorded on the assignment so an assessor can see it was a
/// deliberate choice rather than an oversight." A small team genuinely does
/// need one person to hold two of these, and refusing by default would make
/// the product unusable for exactly the org it is aimed at.
/// </para>
/// <para>
/// A single instance-level switch turns the advisory into a refusal for larger
/// programs. Default OFF.
/// </para>
/// </summary>
public static class SeparationOfDuties
{
    /// <summary>
    /// The conflicts, each with the sentence an assessor should read.
    ///
    /// Both are the same shape: one role does the thing, the other approves it.
    /// That is what separation of duties means here — not that the roles are
    /// unrelated, but that one is the check on the other.
    /// </summary>
    private static readonly (ProjectRole A, ProjectRole B, string Why)[] Conflicts =
    [
        (ProjectRole.LeadDev, ProjectRole.InfoSecOfficer,
            "Lead Dev + InfoSec Officer — remediates and accepts risk on the same finding."),
        (ProjectRole.Architect, ProjectRole.InfoSecOfficer,
            "Architect + InfoSec Officer — authors the waiver and approves it."),
    ];

    /// <summary>
    /// Conflicts introduced by holding <paramref name="roles"/> together.
    /// Empty when there are none.
    /// </summary>
    public static IReadOnlyList<string> Check(IEnumerable<ProjectRole> roles)
    {
        ArgumentNullException.ThrowIfNull(roles);

        var held = roles.ToHashSet();
        return Conflicts
            .Where(c => held.Contains(c.A) && held.Contains(c.B))
            .Select(c => c.Why)
            .ToArray();
    }

    /// <summary>
    /// Would granting <paramref name="incoming"/> to someone who already holds
    /// <paramref name="existing"/> create a conflict?
    ///
    /// Separate from <see cref="Check"/> because the grant dialog needs to show
    /// the advisory BEFORE committing — "see the SoD advisory inline before
    /// granting" — and only the newly introduced conflicts are relevant there.
    /// Repeating a conflict the person already had would be noise.
    /// </summary>
    public static IReadOnlyList<string> WouldIntroduce(
        IEnumerable<ProjectRole> existing, IEnumerable<ProjectRole> incoming)
    {
        ArgumentNullException.ThrowIfNull(existing);
        ArgumentNullException.ThrowIfNull(incoming);

        var before = Check(existing).ToHashSet();
        var after = Check(existing.Concat(incoming));

        return after.Where(c => !before.Contains(c)).ToArray();
    }

    /// <summary>
    /// Is this combination in conflict at all? Convenience for the People
    /// table's SoD flag column.
    /// </summary>
    public static bool IsConflicted(IEnumerable<ProjectRole> roles) => Check(roles).Count > 0;
}
