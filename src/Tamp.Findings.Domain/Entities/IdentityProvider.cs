namespace Tamp.Findings.Domain.Entities;

// A configured way to sign in (TFND-111).
//
// Authentication used to be GitHub OAuth read from environment variables and
// registered conditionally at startup. That works for one provider on one
// deployment and fails the moment an operator needs a second one, or needs to
// turn one off at 2am without a redeploy.
//
// The row is the source of truth and the running schemes are derived from it,
// which is what makes "adding and disabling a provider takes effect without a
// redeploy" true rather than aspirational.
//
// THE SECRET IS ENCRYPTED AT REST AND NEVER RENDERED BACK. It has to be
// decryptable — a handler needs the real value — so this is encryption rather
// than hashing, and the keys live in the database beside it so a container
// restart does not orphan every secret on the instance.
public sealed class IdentityProvider
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public IdentityProviderKind Kind { get; set; }

    // The ASP.NET authentication scheme name, and the segment in
    // /auth/login/{scheme}. URL-safe and immutable once created: changing it
    // would break every bookmark and every in-flight callback.
    public required string Scheme { get; set; }

    // What the sign-in button says. "Sign in with Acme SSO" rather than the
    // scheme name, which is a slug.
    public required string DisplayName { get; set; }

    // Disabled providers keep their configuration. Turning one off during an
    // incident should not mean re-entering a client secret to turn it back on.
    public bool Enabled { get; set; } = true;

    public required string ClientId { get; set; }

    // Protected with ASP.NET Data Protection. Null means "not set yet" — the
    // edit form leaves it alone when the field is left blank, so an operator
    // can rename a provider without re-typing a secret they may not have.
    public string? ProtectedClientSecret { get; set; }

    // OIDC only: the issuer. The handler discovers its endpoints from
    // {Authority}/.well-known/openid-configuration, which is why an OIDC
    // provider needs no endpoint fields and an OAuth one would.
    public string? Authority { get; set; }

    // Space-separated, provider-specific. Stored as authored rather than
    // parsed so an operator sees back exactly what they typed.
    public string? Scopes { get; set; }

    // Require an MFA assertion from this provider.
    //
    // Only meaningful where the provider can actually assert one: an OIDC
    // provider returns `amr`, and GitHub OAuth does not. Setting it on a
    // provider that cannot assert MFA would be a control that silently does
    // nothing, so the service refuses it rather than storing a comforting lie.
    public bool RequireMfa { get; set; }

    public Guid? CreatedByUserId { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;

    // When a sign-in last completed through this provider. A provider nobody
    // has used since it was configured is either redundant or broken, and both
    // are worth seeing.
    public DateTimeOffset? LastSignInAt { get; set; }
}

public enum IdentityProviderKind
{
    // The existing path, moved into the registry.
    GitHubOAuth = 0,

    // Any OpenID Connect issuer — Entra, Okta, Keycloak, Auth0. Discovery
    // means one implementation covers all of them.
    Oidc = 1,
}
