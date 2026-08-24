using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;
using Tamp.Findings.Application.SystemAdmin;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Api.Authentication;

/// <summary>
/// Registering authentication schemes from the database, at runtime
/// (TFND-111).
///
/// This is the piece that makes "adding and disabling a provider takes effect
/// without a redeploy" true. ASP.NET normally fixes its schemes at startup —
/// <c>AddOAuth("GitHub", ...)</c> in <c>Program.cs</c> and that is the set for
/// the life of the process. Here the rows are the source of truth, and the
/// running schemes are rebuilt from them.
///
/// Two moving parts, and both are necessary:
///
///  - <see cref="DynamicSchemeRegistry"/> adds and removes schemes on
///    <see cref="IAuthenticationSchemeProvider"/>.
///  - <see cref="DynamicOAuthOptions"/> / <see cref="DynamicOidcOptions"/>
///    supply the per-scheme options, because the options system caches by name
///    and a scheme registered without configured options fails at challenge
///    time rather than at registration time.
///
/// The cache is invalidated on every rebuild. Without that, rotating a secret
/// would take effect only after a restart — which is exactly the thing this was
/// built to avoid, and it would fail silently: the old secret keeps working
/// until the provider revokes it.
/// </summary>
public sealed class DynamicSchemeRegistry
{
    private readonly IAuthenticationSchemeProvider _schemes;
    private readonly IOptionsMonitorCache<OAuthOptions> _oauthCache;
    private readonly IOptionsMonitorCache<OpenIdConnectOptions> _oidcCache;
    private readonly DynamicProviderStore _store;
    private readonly ILogger<DynamicSchemeRegistry> _log;

    // Guards a rebuild against itself. Two requests arriving together after a
    // provider change would otherwise both rebuild, and AddScheme throws on a
    // duplicate name.
    private readonly SemaphoreSlim _gate = new(1, 1);

    public DynamicSchemeRegistry(
        IAuthenticationSchemeProvider schemes,
        IOptionsMonitorCache<OAuthOptions> oauthCache,
        IOptionsMonitorCache<OpenIdConnectOptions> oidcCache,
        DynamicProviderStore store,
        ILogger<DynamicSchemeRegistry> log)
    {
        _schemes = schemes;
        _oauthCache = oauthCache;
        _oidcCache = oidcCache;
        _store = store;
        _log = log;
    }

    /// <summary>
    /// Rebuild the scheme set from the database.
    ///
    /// Called at startup and after any change to the registry. Idempotent: it
    /// removes what it added last time before adding again, so a rotated secret
    /// or a renamed button takes effect on the next challenge.
    /// </summary>
    public async Task RebuildAsync(CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct);
        try
        {
            IReadOnlyList<ProviderConfiguration> configured;
            try
            {
                configured = await _store.LoadAsync(ct);
            }
            catch (Exception ex)
            {
                // A database that is not reachable yet — first start, a
                // migration still running — must not take the host down. The
                // instance comes up with whatever schemes it had, which on a
                // cold start is none, and the sign-in page says so.
                _log.LogWarning(ex, "Could not load identity providers; keeping the current schemes.");
                return;
            }

            foreach (var scheme in _store.Registered)
            {
                _schemes.RemoveScheme(scheme);
                _oauthCache.TryRemove(scheme);
                _oidcCache.TryRemove(scheme);
            }

            var registered = new List<string>(configured.Count);

            foreach (var provider in configured)
            {
                // A scheme colliding with a statically registered one — the
                // cookie scheme, or a GitHub scheme still wired from config —
                // is a configuration mistake, not a crash. Skip it and say so.
                if (await _schemes.GetSchemeAsync(provider.Scheme) is not null)
                {
                    _log.LogWarning(
                        "Identity provider {Scheme} collides with a scheme registered at startup; skipping.",
                        provider.Scheme);
                    continue;
                }

                _store.Configure(provider);

                var handlerType = provider.Kind switch
                {
                    IdentityProviderKind.Oidc => typeof(OpenIdConnectHandler),
                    _ => typeof(OAuthHandler<OAuthOptions>),
                };

                _schemes.AddScheme(new AuthenticationScheme(
                    provider.Scheme, provider.DisplayName, handlerType));

                registered.Add(provider.Scheme);
            }

            _store.Registered = registered;
            _log.LogInformation("Identity providers registered: {Count}.", registered.Count);
        }
        finally
        {
            _gate.Release();
        }
    }
}

/// <summary>
/// The bridge between the scoped <see cref="IdentityProviderService"/> and the
/// singleton options system.
///
/// It exists because those two live in different lifetimes: options
/// configuration is resolved once as a singleton, and reading the database
/// needs a scope. Holding decrypted configuration here rather than re-reading
/// per request is deliberate — it keeps the number of places a plaintext secret
/// exists to one, and that one is invalidated on every rebuild.
/// </summary>
public sealed class DynamicProviderStore
{
    private readonly IServiceScopeFactory _scopes;
    private readonly Dictionary<string, ProviderConfiguration> _configured = new(StringComparer.Ordinal);

    public DynamicProviderStore(IServiceScopeFactory scopes) => _scopes = scopes;

    /// <summary>Schemes this registry added last rebuild, so it can remove them.</summary>
    public IReadOnlyList<string> Registered { get; set; } = [];

    public async Task<IReadOnlyList<ProviderConfiguration>> LoadAsync(CancellationToken ct)
    {
        using var scope = _scopes.CreateScope();
        var service = scope.ServiceProvider.GetRequiredService<IdentityProviderService>();
        return await service.ConfigurationsAsync(ct);
    }

    public void Configure(ProviderConfiguration provider) => _configured[provider.Scheme] = provider;

    public ProviderConfiguration? For(string scheme) =>
        _configured.TryGetValue(scheme, out var provider) ? provider : null;

    /// <summary>Every configured provider, for the sign-in page's button list.</summary>
    public IReadOnlyList<ProviderConfiguration> All => _configured.Values.ToArray();
}

/// <summary>
/// Options for a database-registered OAuth scheme.
///
/// Only GitHub is modelled as raw OAuth. Anything else should be OIDC — OAuth
/// 2.0 alone says nothing about identity, so every non-OIDC provider needs its
/// own hand-written profile mapping, and adding those one at a time is how a
/// registry turns back into a pile of special cases.
/// </summary>
public sealed class DynamicOAuthOptions : IConfigureNamedOptions<OAuthOptions>
{
    private readonly DynamicProviderStore _store;

    public DynamicOAuthOptions(DynamicProviderStore store) => _store = store;

    public void Configure(OAuthOptions options) { }

    public void Configure(string? name, OAuthOptions options)
    {
        if (name is null || _store.For(name) is not { } provider) return;
        if (provider.Kind != IdentityProviderKind.GitHubOAuth) return;

        // The session lands in the cookie scheme. The OAuth handler is only
        // used for the challenge round-trip, never as a session of its own.
        options.SignInScheme = AuthExtensions.CookieScheme;
        options.ClientId = provider.ClientId;
        options.ClientSecret = provider.ClientSecret;

        // The callback path carries the scheme, so two GitHub providers — a
        // production OAuth app and a staging one — do not collide.
        options.CallbackPath = $"/auth/{provider.Scheme}/callback";

        options.AuthorizationEndpoint = "https://github.com/login/oauth/authorize";
        options.TokenEndpoint = "https://github.com/login/oauth/access_token";
        options.UserInformationEndpoint = "https://api.github.com/user";

        options.Scope.Clear();
        foreach (var scope in provider.Scopes.Count > 0 ? provider.Scopes : ["read:user", "user:email"])
            options.Scope.Add(scope);

        // Never persisted. The access token is used once, during the ticket
        // callback, and keeping it would be storing a credential this product
        // has no further use for.
        options.SaveTokens = false;

        options.Events = new OAuthEvents
        {
            OnCreatingTicket = AuthExtensions.HandleGitHubTicket,
            OnRemoteFailure = AuthExtensions.HandleRemoteFailure,
        };
    }
}

/// <summary>
/// Options for a database-registered OIDC scheme.
///
/// One handler covers Entra, Okta, Keycloak and Auth0, because discovery reads
/// the endpoints from the authority. That is the whole reason OIDC is the
/// second provider kind and not, say, "Okta".
/// </summary>
public sealed class DynamicOidcOptions : IConfigureNamedOptions<OpenIdConnectOptions>
{
    private readonly DynamicProviderStore _store;

    public DynamicOidcOptions(DynamicProviderStore store) => _store = store;

    public void Configure(OpenIdConnectOptions options) { }

    public void Configure(string? name, OpenIdConnectOptions options)
    {
        if (name is null || _store.For(name) is not { } provider) return;
        if (provider.Kind != IdentityProviderKind.Oidc) return;

        options.SignInScheme = AuthExtensions.CookieScheme;
        options.Authority = provider.Authority;
        options.ClientId = provider.ClientId;
        options.ClientSecret = provider.ClientSecret;

        options.CallbackPath = $"/auth/{provider.Scheme}/callback";
        options.SignedOutCallbackPath = $"/auth/{provider.Scheme}/signedout";

        // Authorization code with PKCE. Implicit and hybrid flows put tokens in
        // the browser's address bar, which is where they end up in server logs
        // and referrers.
        options.ResponseType = "code";
        options.UsePkce = true;

        options.Scope.Clear();
        options.Scope.Add("openid");
        options.Scope.Add("profile");
        options.Scope.Add("email");
        foreach (var scope in provider.Scopes) options.Scope.Add(scope);

        options.GetClaimsFromUserInfoEndpoint = true;
        options.SaveTokens = false;

        // Discovery is https-only (validated when the provider is saved), so
        // leave metadata retrieval requiring it. Turning this off is the usual
        // way a dev-time shortcut reaches production.
        options.RequireHttpsMetadata = true;

        options.Events = new OpenIdConnectEvents
        {
            OnTokenValidated = AuthExtensions.HandleOidcTicket,
            // The same last gate the GitHub scheme uses. Both providers refuse
            // through one guard, checked against the principal itself, rather
            // than depending on two different handlers' Fail() semantics.
            OnTicketReceived = AuthExtensions.HandleTicketReceived,
            OnRemoteFailure = ctx =>
            {
                ctx.Response.Redirect($"/signin?error={AuthExtensions.FailureReason(ctx.Failure)}");
                ctx.HandleResponse();
                return Task.CompletedTask;
            },
        };
    }
}
