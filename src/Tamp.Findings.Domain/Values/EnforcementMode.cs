namespace Tamp.Findings.Domain.Values;

// How gate verdicts are enforced (TFND-147 / ADR 0004).
//
// Ordered on purpose: a higher value is STRICTER, so the locked-floor
// resolution (EnforcementResolution) can take the max of the floor and the
// requested mode. Advisory is 0 so it is the default value of a new column and
// of a fresh install — the community runs loose and is never blocked by
// default; the platform team flips it strict.
public enum EnforcementMode
{
    // Evaluate and report, but never fail the build. The OSS-safe default and
    // the honest-preview state: the dashboard and check-run still go red.
    Advisory = 0,

    // A blocking verdict — Fail, Unknown, Error — or an unreachable/no-verdict
    // situation returns non-zero. Fail-closed.
    Enforcing = 1,
}
