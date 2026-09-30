namespace Tamp.Findings.Domain.Risk;

/// <summary>
/// One control posture check (TFND-212): a small, declarative "is this good
/// practice actually configured" signal that produces pass/fail evidence a gate
/// can bite on, and that maps to the NIST controls it provides evidence for.
///
/// The point is to move a whole class of process/config controls — branch
/// protection, required reviews, signed commits, org 2FA — from the stopgap
/// "Inherited" disposition (ADR 0015 walk) to genuinely Owned/Gated, because we
/// actually check them. A check is findings-owned CONTENT (like the archetype
/// layers): the producer reports the raw setting as a fact, findings owns which
/// checks exist, what they gate, and which controls they satisfy.
/// </summary>
public sealed record PostureCheck(
    string Id,
    string Title,
    string Description,
    string GateKey,
    IReadOnlyList<string> ControlRefs);

/// <summary>
/// The built-in registry of posture checks. Starts small and high-value; the
/// framework's whole reason to exist is that adding a check is a one-line entry
/// here plus a producer that reports the setting. DB-distributable content packs
/// are the same follow-up as the archetype layers.
/// </summary>
public static class PostureChecks
{
    public static readonly IReadOnlyList<PostureCheck> All =
    [
        new("branch-protection",
            "Branch protection on the default branch",
            "The default branch cannot be force-pushed or deleted and requires status checks to pass — the baseline that makes every other change-control guarantee enforceable.",
            GateKeys.BranchProtection,
            ["CM-3", "CM-5", "CM-5(1)"]),

        new("pr-reviews-required",
            "Pull-request review required before merge",
            "Changes to the default branch land only through a reviewed pull request (no direct pushes), with at least one required approving review — automated, enforced change control.",
            GateKeys.PrReviewsRequired,
            ["CM-3", "CM-3(1)", "CM-4"]),

        new("signed-commits",
            "Signed commits / signed tags required",
            "Commits (or tags) on the default branch must carry a verified signature, binding each change to an authenticated author — integrity of the change record.",
            GateKeys.SignedCommits,
            ["CM-5(1)", "SI-7"]),

        new("org-2fa",
            "Two-factor authentication enforced org-wide",
            "The organization requires 2FA/MFA for every member, so a compromised password alone cannot author or approve a change.",
            GateKeys.OrgTwoFactor,
            ["IA-2", "IA-2(1)", "IA-2(2)"]),

        new("codeowners",
            "CODEOWNERS present and review-routing enforced",
            "A CODEOWNERS file routes changes to the accountable owners and their review is required — separation of duties on change approval.",
            GateKeys.Codeowners,
            ["CM-3(1)", "AC-5"]),
    ];

    public static PostureCheck? ById(string id) =>
        All.FirstOrDefault(c => string.Equals(c.Id, id, System.StringComparison.OrdinalIgnoreCase));

    /// <summary>The gate key → check, for the evaluator and the control→gate map.</summary>
    public static PostureCheck? ByGateKey(string gateKey) =>
        All.FirstOrDefault(c => c.GateKey == gateKey);
}
