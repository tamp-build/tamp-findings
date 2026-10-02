namespace Tamp.Findings.Domain.Values;

/// <summary>
/// The result of a control posture check (TFND-212). Deliberately four-valued,
/// like the gate verdicts it feeds: a check with no observation is
/// <see cref="Unknown"/> (which blocks a required gate) — never a silent Pass,
/// because "we never looked at branch protection" is not "branch protection is on."
/// </summary>
public enum PostureStatus
{
    /// <summary>No observation on file — unassessed. A required gate reads this as a block.</summary>
    Unknown = 0,
    /// <summary>The posture requirement is met (branch protection on, reviews required, …).</summary>
    Pass = 1,
    /// <summary>The posture requirement is not met.</summary>
    Fail = 2,
    /// <summary>The check does not apply to this project (e.g. an org-2FA check on a non-org repo).</summary>
    NotApplicable = 3,
}
