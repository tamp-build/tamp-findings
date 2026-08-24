using Microsoft.AspNetCore.Authentication;
using Tamp.Findings.Application.Authentication;

namespace Tamp.Findings.Api.Authentication;

/// <summary>
/// Builds the sign-in button list from the two places a provider can come from.
///
/// The registry (TFND-111) is the modern path and the only one an operator can
/// change without a redeploy. The built-in GitHub scheme predates it and is
/// still how existing deployments authenticate — including this project's own
/// cluster, which has no provider rows at all.
///
/// Both are listed, because a page driven only by the registry would show NO
/// buttons on any instance still using the environment variables. That is not a
/// cosmetic regression: it locks every user out of a working instance, and the
/// person best placed to fix it is locked out too.
/// </summary>
public sealed class SignInOptionsProvider : ISignInOptions
{
    private readonly DynamicProviderStore _store;
    private readonly IAuthenticationSchemeProvider _schemes;

    public SignInOptionsProvider(DynamicProviderStore store, IAuthenticationSchemeProvider schemes)
    {
        _store = store;
        _schemes = schemes;
    }

    public async Task<IReadOnlyList<SignInOption>> AvailableAsync(CancellationToken ct = default)
    {
        var options = new List<SignInOption>();

        // Asked of the scheme provider rather than re-reading the environment:
        // the handler is registered only when both a client id and a secret are
        // present, so "is the scheme there" is the same question as "can this
        // button actually complete a sign-in", and it stays the same question
        // if that registration rule ever changes.
        if (await _schemes.GetSchemeAsync(AuthExtensions.GitHubScheme) is not null)
        {
            options.Add(new SignInOption(
                AuthExtensions.GitHubScheme, "GitHub", "/auth/login/github"));
        }

        // The store holds only providers that are enabled AND hold a secret,
        // so everything here is usable. A provider that is configured but
        // switched off must not appear: a button that is certain to fail is
        // worse than no button, because the visitor cannot tell which.
        foreach (var provider in _store.All)
        {
            // A registry provider that claims the built-in scheme name would
            // otherwise render twice, with two buttons pointing at different
            // routes and no way for a reader to tell which one works. The
            // registry entry wins — it is the one an operator can edit.
            options.RemoveAll(o => string.Equals(o.Scheme, provider.Scheme, StringComparison.OrdinalIgnoreCase));

            options.Add(new SignInOption(
                provider.Scheme,
                provider.DisplayName,
                $"/auth/login/provider/{Uri.EscapeDataString(provider.Scheme)}"));
        }

        return options;
    }
}
