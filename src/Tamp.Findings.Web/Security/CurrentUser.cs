using System.Security.Claims;
using Microsoft.AspNetCore.Components.Authorization;
using Tamp.Findings.Application.Authorization;

namespace Tamp.Findings.Web.Security;

/// <summary>
/// The signed-in user, resolved to a <see cref="Principal"/> at a given scope.
///
/// Every screen from here on needs this: the design disables a gated action and
/// says why rather than hiding it, so a component has to know both whether the
/// reader may act AND the reason if not.
///
/// Deliberately thin. It reads the user id from the authentication state and
/// hands off to <see cref="PrincipalResolver"/>, which loads the assignments
/// and applies scope resolution. Nothing here decides access — that decision
/// lives in Application (ADR 0002), and duplicating even part of it in the UI
/// is how the two drift.
/// </summary>
public sealed class CurrentUser
{
    private readonly AuthenticationStateProvider _auth;
    private readonly PrincipalResolver _resolver;
    private readonly CapabilityEvaluator _capabilities;

    public CurrentUser(
        AuthenticationStateProvider auth,
        PrincipalResolver resolver,
        CapabilityEvaluator capabilities)
    {
        _auth = auth;
        _resolver = resolver;
        _capabilities = capabilities;
    }

    /// <summary>
    /// Resolve at a scope. Returns null when nobody is signed in, or when the
    /// user is not approved — both mean "no principal", and neither should
    /// silently become a Viewer.
    /// </summary>
    public async Task<Principal?> AtAsync(ScopeTarget target, CancellationToken ct = default)
    {
        var state = await _auth.GetAuthenticationStateAsync();
        var claims = state.User;

        if (claims.Identity?.IsAuthenticated != true) return null;

        var raw = claims.FindFirstValue(TampUserIdClaim);
        if (!Guid.TryParse(raw, out var userId)) return null;

        return await _resolver.ResolveAsync(userId, target, ct);
    }

    /// <summary>
    /// Can the signed-in user do this here, and if not, why not.
    ///
    /// Returns a denial rather than throwing when nobody is signed in, so a
    /// component can render a disabled control with an explanation instead of
    /// having to branch on authentication separately.
    /// </summary>
    public async Task<AuthorizationDecision> CanAsync(
        Capability capability, ScopeTarget target, CancellationToken ct = default)
    {
        var principal = await AtAsync(target, ct);
        return principal is null
            ? AuthorizationDecision.Deny("You are not signed in, or your account is awaiting approval.")
            : _capabilities.Evaluate(principal, capability);
    }

    // Duplicated from AuthExtensions rather than referenced: Web must not
    // depend on Api (ADR 0002). The claim type is a wire contract between the
    // two, and a test asserts they still agree.
    public const string TampUserIdClaim = "urn:tamp.findings:userId";
}
