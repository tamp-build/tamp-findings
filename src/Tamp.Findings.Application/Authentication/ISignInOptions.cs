namespace Tamp.Findings.Application.Authentication;

/// <summary>
/// One way in, as the sign-in page renders it.
/// </summary>
/// <param name="Scheme">The authentication scheme. Stable; used as a key, not shown.</param>
/// <param name="DisplayName">What the button says — "Continue with Google".</param>
/// <param name="LoginPath">
/// Where the button points, WITHOUT query string. Supplied by the
/// implementation because the two kinds of provider live at different routes:
/// the built-in GitHub scheme at /auth/login/github and registry providers at
/// /auth/login/provider/{scheme}. Handing the page a finished path keeps it
/// from having to know that, and from getting it wrong for one of them.
/// </param>
public sealed record SignInOption(string Scheme, string DisplayName, string LoginPath);

/// <summary>
/// The sign-in methods this instance can actually complete right now.
///
/// Deliberately narrow. It returns names and paths and nothing else: an
/// anonymous visitor learns which buttons exist, never a client id, an
/// authority, or anything shaped like configuration.
///
/// Lives in Application because the sign-in page needs it and the Web RCL
/// cannot reference the host — the host references IT. The implementation is
/// in the API project, where the scheme registry and the provider store live.
/// </summary>
public interface ISignInOptions
{
    /// <summary>
    /// Every usable provider. An EMPTY result is meaningful and must be
    /// rendered as such: it means nobody can sign in, which is a
    /// misconfiguration the page should state plainly rather than present as a
    /// page with no buttons on it.
    /// </summary>
    Task<IReadOnlyList<SignInOption>> AvailableAsync(CancellationToken ct = default);
}
