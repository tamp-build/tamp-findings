using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Api.Authentication;
using Tamp.Findings.Application.SystemAdmin;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Api.Tests;

// What the sign-in page offers (TFND-111 built the registry; the page only ever
// rendered a hardcoded GitHub button, so a provider added through the admin
// screen had a working endpoint and nothing pointing at it).
//
// The list has to span both places a provider can come from. The registry is
// the modern path; the built-in GitHub scheme predates it and is still how
// existing deployments authenticate, including this project's own cluster,
// which has no provider rows at all. A page driven only by the registry shows
// no buttons there — and that locks out the person who would fix it.
public class SignInOptionsTests
{
    [Fact]
    public async Task The_built_in_github_scheme_is_offered_when_it_is_registered()
    {
        var options = await Build(githubRegistered: true).AvailableAsync();

        var only = Assert.Single(options);
        Assert.Equal("GitHub", only.DisplayName);
        Assert.Equal("/auth/login/github", only.LoginPath);
    }

    [Fact]
    public async Task Nothing_is_offered_when_no_provider_can_complete_a_sign_in()
    {
        // Empty is a real answer, not a failure to load. The page renders it as
        // "no way to sign in", which is what an operator needs to read.
        Assert.Empty(await Build(githubRegistered: false).AvailableAsync());
    }

    [Fact]
    public async Task Registry_providers_are_offered_at_the_dynamic_route()
    {
        var options = await Build(githubRegistered: false, Provider("google", "Google")).AvailableAsync();

        var only = Assert.Single(options);
        Assert.Equal("Google", only.DisplayName);
        Assert.Equal("/auth/login/provider/google", only.LoginPath);
    }

    [Fact]
    public async Task A_deployment_can_offer_the_built_in_scheme_and_registry_providers_together()
    {
        // The point of the change. Adding Google must not remove the GitHub
        // button that everyone currently signs in with.
        var options = await Build(
            githubRegistered: true,
            Provider("google", "Google"),
            Provider("entra", "Microsoft")).AvailableAsync();

        Assert.Equal(
            ["GitHub", "Google", "Microsoft"],
            options.Select(o => o.DisplayName).OrderBy(n => n, StringComparer.Ordinal).ToArray());
    }

    [Fact]
    public async Task A_registry_provider_that_claims_the_built_in_scheme_name_replaces_it()
    {
        // Otherwise the page renders two buttons with the same name pointing at
        // different routes, and no reader can tell which one works. The
        // registry entry wins because it is the one an operator can edit.
        var options = await Build(githubRegistered: true, Provider("GitHub", "GitHub Enterprise")).AvailableAsync();

        var only = Assert.Single(options);
        Assert.Equal("GitHub Enterprise", only.DisplayName);
        Assert.Equal("/auth/login/provider/GitHub", only.LoginPath);
    }

    [Fact]
    public async Task A_scheme_name_needing_encoding_is_escaped_into_the_path()
    {
        var options = await Build(githubRegistered: false, Provider("acme sso", "Acme")).AvailableAsync();

        Assert.Equal("/auth/login/provider/acme%20sso", Assert.Single(options).LoginPath);
    }

    private static ProviderConfiguration Provider(string scheme, string displayName) =>
        new(scheme, IdentityProviderKind.Oidc, displayName,
            ClientId: "id", ClientSecret: "secret",
            Authority: "https://issuer.example", Scopes: ["openid"], RequireMfa: false);

    private static SignInOptionsProvider Build(bool githubRegistered, params ProviderConfiguration[] configured)
    {
        // The scope factory is only reached by LoadAsync, which this never
        // calls — the store is populated directly, the way the scheme registry
        // populates it at startup.
        var store = new DynamicProviderStore(new ServiceCollection().BuildServiceProvider()
            .GetRequiredService<IServiceScopeFactory>());

        foreach (var provider in configured) store.Configure(provider);

        return new SignInOptionsProvider(store, new StubSchemeProvider(githubRegistered));
    }

    // Only GetSchemeAsync is exercised; the rest of the interface exists to
    // satisfy the compiler.
    private sealed class StubSchemeProvider : IAuthenticationSchemeProvider
    {
        private readonly bool _github;

        public StubSchemeProvider(bool github) => _github = github;

        public Task<AuthenticationScheme?> GetSchemeAsync(string name) =>
            Task.FromResult(_github && name == AuthExtensions.GitHubScheme
                ? new AuthenticationScheme(name, name, typeof(NoopHandler))
                : null);

        public void AddScheme(AuthenticationScheme scheme) { }
        public void RemoveScheme(string name) { }
        public Task<IEnumerable<AuthenticationScheme>> GetAllSchemesAsync() => Task.FromResult<IEnumerable<AuthenticationScheme>>([]);
        public Task<AuthenticationScheme?> GetDefaultAuthenticateSchemeAsync() => Task.FromResult<AuthenticationScheme?>(null);
        public Task<AuthenticationScheme?> GetDefaultChallengeSchemeAsync() => Task.FromResult<AuthenticationScheme?>(null);
        public Task<AuthenticationScheme?> GetDefaultForbidSchemeAsync() => Task.FromResult<AuthenticationScheme?>(null);
        public Task<AuthenticationScheme?> GetDefaultSignInSchemeAsync() => Task.FromResult<AuthenticationScheme?>(null);
        public Task<AuthenticationScheme?> GetDefaultSignOutSchemeAsync() => Task.FromResult<AuthenticationScheme?>(null);
        public Task<IEnumerable<AuthenticationScheme>> GetRequestHandlerSchemesAsync() => Task.FromResult<IEnumerable<AuthenticationScheme>>([]);

        private sealed class NoopHandler : IAuthenticationHandler
        {
            public Task<AuthenticateResult> AuthenticateAsync() => throw new NotSupportedException();
            public Task ChallengeAsync(AuthenticationProperties? properties) => throw new NotSupportedException();
            public Task ForbidAsync(AuthenticationProperties? properties) => throw new NotSupportedException();
            public Task InitializeAsync(AuthenticationScheme scheme, HttpContext context) => throw new NotSupportedException();
        }
    }
}
