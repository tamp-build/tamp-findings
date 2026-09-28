namespace Tamp.Findings.Domain.Compliance;

/// <summary>
/// The four-valued conformance verdict (ADR 0001 / ADR 0006). Never collapse to
/// pass/fail: an evaluation that could not answer, or that broke, is categorically
/// different from a fail, and reporting either as a pass is how the evidence
/// becomes false. Unknown and Error both BLOCK — silence is not conformance.
/// </summary>
public enum ConformanceVerdict
{
    Pass = 0,
    Fail = 1,
    /// <summary>No answer — the rule could not be evaluated (e.g. re-anchor
    /// needed). Blocks; never green.</summary>
    Unknown = 2,
    /// <summary>Evaluation broke (operator alerted). Blocks; the last good
    /// verdict is NOT carried forward.</summary>
    Error = 3,
}

/// <summary>How a rule was examined (ADR 0006). Drives the method badge and
/// whether a verify pass applies.</summary>
public enum ConformanceMethod
{
    /// <summary>A pure predicate — reproducible, no model. Recomputable.</summary>
    Deterministic = 0,
    /// <summary>A mid-tier model judged it; frozen at the snapshot.</summary>
    Semantic = 1,
    /// <summary>An adversarial verify pass over a semantic verdict.</summary>
    Verify = 2,
}

/// <summary>The result of a verify pass over a semantic verdict (ADR 0006).
/// Hidden when there is no verdict to verify (deterministic rules).</summary>
public enum VerifyOutcome
{
    NotRun = 0,
    Confirmed = 1,
    Disputed = 2,
}
