using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.SystemAdmin;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Integration.Tests;

// The identity-provider registry (TFND-111).
//
// The ticket's three acceptance criteria are the spine of this file: adding and
// disabling take effect without a redeploy, secrets are write-only and never
// rendered back, and every change writes an access-class audit entry.
[Collection(DatabaseCollection.Name)]
public class IdentityProviderIntegrationTests
{
    private readonly DatabaseFixture _fx;

    public IdentityProviderIntegrationTests(DatabaseFixture fx) => _fx = fx;

    private static ProviderDraft Oidc(string suffix, string? secret = "s3cret") => new(
        IdentityProviderKind.Oidc,
        $"acme-{suffix}",
        "Acme SSO",
        "client-id",
        secret,
        "https://login.acme.test",
        null,
        Enabled: true,
        RequireMfa: false);

    // ---- Secrets ------------------------------------------------------------

    [SkippableFact]
    public async Task A_secret_is_never_returned_by_the_listing()
    {
        Skip.IfNot(_fx.Available);

        // The strongest form of "never rendered back": ProviderRow has no shape
        // that could carry one, so this asserts the ciphertext is not hiding in
        // any string on it either.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var providers = scope.ServiceProvider.GetRequiredService<IdentityProviderService>();
        var db = _fx.Db(scope);

        await providers.SaveAsync(world.Admin, null, Oidc(world.Suffix, "the-real-secret"));

        var row = (await providers.ListAsync()).Single(p => p.Scheme == $"acme-{world.Suffix}");
        var stored = await db.IdentityProviders.SingleAsync(p => p.Scheme == $"acme-{world.Suffix}");

        Assert.True(row.HasSecret);
        var rendered = string.Join('|', row.ToString());
        Assert.DoesNotContain("the-real-secret", rendered, StringComparison.Ordinal);
        Assert.DoesNotContain(stored.ProtectedClientSecret!, rendered, StringComparison.Ordinal);
    }

    [SkippableFact]
    public async Task A_secret_is_encrypted_at_rest()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var providers = scope.ServiceProvider.GetRequiredService<IdentityProviderService>();
        var db = _fx.Db(scope);

        await providers.SaveAsync(world.Admin, null, Oidc(world.Suffix, "the-real-secret"));

        var stored = await db.IdentityProviders.SingleAsync(p => p.Scheme == $"acme-{world.Suffix}");

        Assert.NotNull(stored.ProtectedClientSecret);
        Assert.DoesNotContain("the-real-secret", stored.ProtectedClientSecret!, StringComparison.Ordinal);
    }

    [SkippableFact]
    public async Task A_blank_secret_on_an_edit_keeps_the_stored_one()
    {
        Skip.IfNot(_fx.Available);

        // Renaming a provider must not require re-typing a secret the operator
        // may no longer have — that is how people end up keeping secrets in a
        // second place so they can paste them back.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var providers = scope.ServiceProvider.GetRequiredService<IdentityProviderService>();
        var db = _fx.Db(scope);

        var created = await providers.SaveAsync(world.Admin, null, Oidc(world.Suffix, "original"));
        var before = (await db.IdentityProviders.AsNoTracking()
            .SingleAsync(p => p.Id == created.Value)).ProtectedClientSecret;

        await providers.SaveAsync(
            world.Admin, created.Value, Oidc(world.Suffix, secret: null) with { DisplayName = "Renamed" });

        var after = await db.IdentityProviders.AsNoTracking().SingleAsync(p => p.Id == created.Value);

        Assert.Equal(before, after.ProtectedClientSecret);
        Assert.Equal("Renamed", after.DisplayName);
    }

    [SkippableFact]
    public async Task A_new_provider_without_a_secret_is_refused()
    {
        Skip.IfNot(_fx.Available);

        // Creating one that cannot work is how an operator ends up with a
        // sign-in button that fails at the far end.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var providers = scope.ServiceProvider.GetRequiredService<IdentityProviderService>();

        var result = await providers.SaveAsync(world.Admin, null, Oidc(world.Suffix, secret: null));

        Assert.False(result.Success);
        Assert.False(result.WasDenied);
    }

    [SkippableFact]
    public async Task The_configuration_path_decrypts_the_secret()
    {
        Skip.IfNot(_fx.Available);

        // The one place a plaintext secret exists, and it has one caller: the
        // authentication layer.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var providers = scope.ServiceProvider.GetRequiredService<IdentityProviderService>();

        await providers.SaveAsync(world.Admin, null, Oidc(world.Suffix, "round-trip"));

        var configured = (await providers.ConfigurationsAsync())
            .Single(p => p.Scheme == $"acme-{world.Suffix}");

        Assert.Equal("round-trip", configured.ClientSecret);
    }

    // ---- Enabling and disabling ---------------------------------------------

    [SkippableFact]
    public async Task A_disabled_provider_is_not_offered_for_registration()
    {
        Skip.IfNot(_fx.Available);

        // "Takes effect without a redeploy" begins here: the host rebuilds its
        // schemes from exactly this list.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var providers = scope.ServiceProvider.GetRequiredService<IdentityProviderService>();

        var created = await providers.SaveAsync(world.Admin, null, Oidc(world.Suffix));
        Assert.Contains(await providers.ConfigurationsAsync(), p => p.Scheme == $"acme-{world.Suffix}");

        await providers.SaveAsync(world.Admin, created.Value, Oidc(world.Suffix, null) with { Enabled = false });

        Assert.DoesNotContain(await providers.ConfigurationsAsync(), p => p.Scheme == $"acme-{world.Suffix}");
    }

    [SkippableFact]
    public async Task A_disabled_provider_keeps_its_configuration()
    {
        Skip.IfNot(_fx.Available);

        // Turning one off during an incident should not mean re-entering a
        // client secret to turn it back on.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var providers = scope.ServiceProvider.GetRequiredService<IdentityProviderService>();

        var created = await providers.SaveAsync(world.Admin, null, Oidc(world.Suffix, "kept"));
        await providers.SaveAsync(world.Admin, created.Value, Oidc(world.Suffix, null) with { Enabled = false });
        await providers.SaveAsync(world.Admin, created.Value, Oidc(world.Suffix, null) with { Enabled = true });

        var configured = (await providers.ConfigurationsAsync())
            .Single(p => p.Scheme == $"acme-{world.Suffix}");

        Assert.Equal("kept", configured.ClientSecret);
    }

    // ---- Rules --------------------------------------------------------------

    [SkippableFact]
    public async Task The_scheme_cannot_change_on_an_edit()
    {
        Skip.IfNot(_fx.Available);

        // It is in the callback URL registered with the provider at the far
        // end and in every bookmark. Changing it would break both, silently.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var providers = scope.ServiceProvider.GetRequiredService<IdentityProviderService>();

        var created = await providers.SaveAsync(world.Admin, null, Oidc(world.Suffix));

        var result = await providers.SaveAsync(
            world.Admin, created.Value, Oidc(world.Suffix, null) with { Scheme = $"renamed-{world.Suffix}" });

        Assert.False(result.Success);
        Assert.Contains("callback URL", result.Error!, StringComparison.OrdinalIgnoreCase);
    }

    [SkippableFact]
    public async Task Two_providers_cannot_share_a_scheme()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var providers = scope.ServiceProvider.GetRequiredService<IdentityProviderService>();

        await providers.SaveAsync(world.Admin, null, Oidc(world.Suffix));
        var second = await providers.SaveAsync(world.Admin, null, Oidc(world.Suffix));

        Assert.False(second.Success);
    }

    [SkippableFact]
    public async Task An_oidc_authority_must_be_https()
    {
        Skip.IfNot(_fx.Available);

        // Discovery over http would expose the token endpoint to whoever is
        // between this instance and the issuer.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var providers = scope.ServiceProvider.GetRequiredService<IdentityProviderService>();

        var result = await providers.SaveAsync(
            world.Admin, null, Oidc(world.Suffix) with { Authority = "http://login.acme.test" });

        Assert.False(result.Success);
        Assert.Contains("https", result.Error!, StringComparison.OrdinalIgnoreCase);
    }

    [SkippableFact]
    public async Task A_provider_that_cannot_assert_mfa_cannot_be_marked_as_requiring_it()
    {
        Skip.IfNot(_fx.Available);

        // A requirement against a provider that cannot assert MFA would be a
        // control that silently does nothing — worse than no control, because
        // somebody would believe it.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var providers = scope.ServiceProvider.GetRequiredService<IdentityProviderService>();

        var result = await providers.SaveAsync(world.Admin, null, new ProviderDraft(
            IdentityProviderKind.GitHubOAuth, $"gh-{world.Suffix}", "GitHub", "id", "secret",
            null, null, Enabled: true, RequireMfa: true));

        Assert.False(result.Success);
        Assert.Contains("cannot assert MFA", result.Error!, StringComparison.OrdinalIgnoreCase);
    }

    [SkippableFact]
    public async Task A_scheme_with_url_unsafe_characters_is_refused()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var providers = scope.ServiceProvider.GetRequiredService<IdentityProviderService>();

        var result = await providers.SaveAsync(
            world.Admin, null, Oidc(world.Suffix) with { Scheme = "acme sso/prod" });

        Assert.False(result.Success);
    }

    [SkippableFact]
    public async Task The_last_enabled_provider_cannot_be_removed()
    {
        Skip.IfNot(_fx.Available);

        // An instance with no way in is recoverable only through the database,
        // and the person who did it is usually the one who cannot get back in.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var providers = scope.ServiceProvider.GetRequiredService<IdentityProviderService>();
        var db = _fx.Db(scope);

        // Make this the only enabled provider on the instance.
        await db.IdentityProviders.ExecuteUpdateAsync(s => s.SetProperty(p => p.Enabled, false));
        var created = await providers.SaveAsync(world.Admin, null, Oidc(world.Suffix));

        var result = await providers.DeleteAsync(world.Admin, created.Value);

        Assert.False(result.Success);
        Assert.Contains("only enabled sign-in provider", result.Error!, StringComparison.OrdinalIgnoreCase);
    }

    [SkippableFact]
    public async Task An_incomplete_provider_is_flagged_rather_than_looking_healthy()
    {
        Skip.IfNot(_fx.Available);

        // Worse than being off: the sign-in button is there and the round-trip
        // fails at the far end, where the error is somebody else's.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var providers = scope.ServiceProvider.GetRequiredService<IdentityProviderService>();
        var db = _fx.Db(scope);

        var created = await providers.SaveAsync(world.Admin, null, Oidc(world.Suffix));

        // Simulate a key ring loss: the row survives, the secret does not.
        await db.IdentityProviders
            .Where(p => p.Id == created.Value)
            .ExecuteUpdateAsync(s => s.SetProperty(p => p.ProtectedClientSecret, (string?)null));

        var row = (await providers.ListAsync()).Single(p => p.Id == created.Value);

        Assert.True(row.Incomplete);
        Assert.False(row.HasSecret);
    }

    [SkippableFact]
    public async Task A_provider_whose_secret_cannot_be_decrypted_is_skipped_rather_than_registered()
    {
        Skip.IfNot(_fx.Available);

        // An empty ClientSecret makes OAuthOptions.Validate throw on EVERY
        // request, including /health — so one unreadable secret would take the
        // whole instance down.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var providers = scope.ServiceProvider.GetRequiredService<IdentityProviderService>();
        var db = _fx.Db(scope);

        var created = await providers.SaveAsync(world.Admin, null, Oidc(world.Suffix));

        await db.IdentityProviders
            .Where(p => p.Id == created.Value)
            .ExecuteUpdateAsync(s => s.SetProperty(p => p.ProtectedClientSecret, "not-a-protected-payload"));

        var configured = await providers.ConfigurationsAsync();

        Assert.DoesNotContain(configured, p => p.Scheme == $"acme-{world.Suffix}");
    }

    // ---- Audit --------------------------------------------------------------

    [SkippableFact]
    public async Task Adding_a_provider_is_audited_as_an_access_change()
    {
        Skip.IfNot(_fx.Available);

        // A new way in is exactly what an assessor reads first.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var providers = scope.ServiceProvider.GetRequiredService<IdentityProviderService>();
        var db = _fx.Db(scope);

        var created = await providers.SaveAsync(world.Admin, null, Oidc(world.Suffix));

        var entry = db.AuditEntries.Single(a => a.SubjectId == created.Value);

        Assert.Equal(AuditClass.Access, entry.Class);
        Assert.Equal("auth_provider.added", entry.Action);
    }

    [SkippableFact]
    public async Task Disabling_a_provider_says_so_in_the_audit_detail()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var providers = scope.ServiceProvider.GetRequiredService<IdentityProviderService>();
        var db = _fx.Db(scope);

        var created = await providers.SaveAsync(world.Admin, null, Oidc(world.Suffix));
        await providers.SaveAsync(world.Admin, created.Value, Oidc(world.Suffix, null) with { Enabled = false });

        var entry = db.AuditEntries
            .Where(a => a.SubjectId == created.Value)
            .OrderByDescending(a => a.At)
            .First();

        Assert.Equal(AuditClass.Access, entry.Class);
        Assert.Contains("DISABLED", entry.Detail!, StringComparison.Ordinal);
    }

    [SkippableFact]
    public async Task Rotating_a_secret_is_recorded_as_a_rotation()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var providers = scope.ServiceProvider.GetRequiredService<IdentityProviderService>();
        var db = _fx.Db(scope);

        var created = await providers.SaveAsync(world.Admin, null, Oidc(world.Suffix, "first"));
        await providers.SaveAsync(world.Admin, created.Value, Oidc(world.Suffix, "second"));

        var entry = db.AuditEntries
            .Where(a => a.SubjectId == created.Value)
            .OrderByDescending(a => a.At)
            .First();

        Assert.Contains("secret rotated", entry.Detail!, StringComparison.Ordinal);
        // And emphatically not the secret itself.
        Assert.DoesNotContain("second", entry.Detail!, StringComparison.Ordinal);
    }

    [SkippableFact]
    public async Task A_non_admin_cannot_touch_the_registry()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var providers = scope.ServiceProvider.GetRequiredService<IdentityProviderService>();

        var result = await providers.SaveAsync(world.Nobody, null, Oidc(world.Suffix));

        Assert.True(result.WasDenied);
    }

    // ---- Sign-in policy -----------------------------------------------------

    [Theory]
    [InlineData("someone@example.com", true)]
    [InlineData("someone@EXAMPLE.COM", true)]
    [InlineData("someone@other.test", false)]
    [InlineData(null, false)]
    [InlineData("no-at-sign", false)]
    public void The_domain_policy_gates_registration(string? email, bool allowed)
    {
        // A pure function, so it does not need the database — and it is where
        // the rule actually lives, which is the point of testing it directly.
        Assert.Equal(allowed, IdentityProviderService.MayRegister(email, ["example.com"]));
    }

    [Fact]
    public void An_empty_domain_list_allows_everyone()
    {
        // The honest default: a self-hosted instance behind a VPN often has no
        // need for a restriction, and one nobody chose is a support call the
        // first time a contractor signs in.
        Assert.True(IdentityProviderService.MayRegister("anyone@anywhere.test", []));
        Assert.True(IdentityProviderService.MayRegister(null, []));
    }

    [Fact]
    public void Only_oidc_can_assert_mfa()
    {
        Assert.True(IdentityProviderService.CanAssertMfa(IdentityProviderKind.Oidc));
        Assert.False(IdentityProviderService.CanAssertMfa(IdentityProviderKind.GitHubOAuth));
    }

    // ---- Seed ---------------------------------------------------------------

    private sealed record World(string Suffix, Principal Admin, Principal Nobody);

    private async Task<World> SeedAsync()
    {
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);

        var suffix = Guid.NewGuid().ToString("N")[..8];

        var admin = new User
        {
            Login = $"idp-admin-{suffix}", DisplayName = "Admin",
            Email = $"idp-admin-{suffix}@example.test", IsApproved = true, IsAdmin = true,
        };
        var nobody = new User
        {
            Login = $"idp-nobody-{suffix}", DisplayName = "Nobody",
            Email = $"idp-nobody-{suffix}@example.test", IsApproved = true,
        };
        db.Users.AddRange(admin, nobody);
        await db.SaveChangesAsync();

        return new World(
            suffix,
            Principal.For(admin.Id, admin.Login, isAdmin: true, []),
            Principal.For(nobody.Id, nobody.Login, isAdmin: false, []));
    }
}
