namespace Tamp.Findings.Application.Authorization;

/// <summary>
/// The answer to "may this person do this here", with the reason attached.
///
/// A bare bool would be cheaper and worse. The UI is supposed to DISABLE a
/// gated action and say why rather than hide it — "Confirm is disabled with the
/// reason" is the hand-off's own wording for blocked policy deletion — and the
/// audit log wants the same sentence. Both need the reason, so the decision
/// carries it rather than each caller inventing one.
/// </summary>
public sealed record AuthorizationDecision(bool Allowed, string? Reason, bool Conditional = false)
{
    public static AuthorizationDecision Allow() => new(true, null);

    /// <summary>Allowed, but the caller must satisfy a stated condition (the matrix's ◐).</summary>
    public static AuthorizationDecision AllowIf(string condition) => new(true, condition, Conditional: true);

    public static AuthorizationDecision Deny(string reason) => new(false, reason);

    public static implicit operator bool(AuthorizationDecision d) => d.Allowed;
}
