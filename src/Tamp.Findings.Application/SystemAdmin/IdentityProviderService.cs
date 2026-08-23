using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Application.Auditing;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Projects;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Application.SystemAdmin;

/// <summary>
/// The identity-provider registry (TFND-111).
///
/// Authentication used to be GitHub OAuth read from environment variables and
/// registered conditionally at startup. That works for one provider on one
/// deployment and fails the moment an operator needs a second, or needs to turn
/// one off at 2am without a redeploy.
///
/// Three rules the ticket asks for, and each is enforced here rather than in the
/// UI, because a UI rule is a courtesy:
///
///  1. Adding or disabling a provider takes effect without a redeploy. The rows
///     are the source of truth and the running schemes are derived from them.
///  2. Secrets are WRITE-ONLY. Nothing on this class returns one, encrypted or
///     otherwise, and an edit that leaves the field blank keeps what is stored
///     rather than clearing it.
///  3. Every change writes an access-class audit entry. A new way in is exactly
///     what an assessor reads first.
/// </summary>
public sealed class IdentityProviderService
{
    private readonly FindingsDbContext _db;
    private readonly CapabilityEvaluator _capabilities;
    private readonly AuditLog _audit;
    private readonly ProviderSecretProtector _protector;

    public IdentityProviderService(
        FindingsDbContext db, CapabilityEvaluator capabilities, AuditLog audit,
        ProviderSecretProtector protector)
    {
        _db = db;
        _capabilities = capabilities;
        _audit = audit;
        _protector = protector;
    }

    /// <summary>
    /// Providers as the admin screen shows them.
    ///
    /// Note what is NOT on <see cref="ProviderRow"/>: the secret, in any form.
    /// A "•••" placeholder would be harmless; returning the ciphertext to a
    /// browser would not, and the way to never do the second is to never have
    /// the shape that could.
    /// </summary>
    public async Task<IReadOnlyList<ProviderRow>> ListAsync(CancellationToken ct = default)
    {
        var providers = await _db.IdentityProviders.AsNoTracking()
            .Select(p => new
            {
                p.Id, p.Kind, p.Scheme, p.DisplayName, p.Enabled, p.ClientId,
                p.Authority, p.Scopes, p.RequireMfa, p.LastSignInAt, p.UpdatedAt,
                HasSecret = p.ProtectedClientSecret != null,
            })
            .ToArrayAsync(ct);

        // How many people actually sign in through each. A provider nobody uses
        // is either redundant or broken, and both are worth seeing before
        // deciding whether it is safe to remove.
        var githubUsers = await _db.Users.CountAsync(u => u.GitHubUserId != null, ct);

        return providers
            .Select(p => new ProviderRow(
                p.Id, p.Kind, p.Scheme, p.DisplayName, p.Enabled, p.ClientId,
                p.Authority, p.Scopes, p.RequireMfa, p.HasSecret,
                p.Kind == IdentityProviderKind.GitHubOAuth ? githubUsers : 0,
                p.LastSignInAt, p.UpdatedAt,
                // A provider that cannot run is worse than one that is off: the
                // sign-in button is there and the round-trip fails at the far
                // end, where the error is somebody else's.
                Incomplete(p.Kind, p.ClientId, p.HasSecret, p.Authority)))
            .OrderByDescending(p => p.Enabled)
            .ThenBy(p => p.DisplayName, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    public async Task<Result<Guid>> SaveAsync(
        Principal actor, Guid? id, ProviderDraft draft, CancellationToken ct = default)
    {
        var decision = _capabilities.Evaluate(actor, Capability.AssignRoles);
        if (!decision.Allowed) return Result<Guid>.Denied(decision.Reason!);

        if (Validate(draft) is { } invalid) return Result<Guid>.Invalid(invalid);

        IdentityProvider provider;
        bool created;

        if (id is { } existing)
        {
            var found = await _db.IdentityProviders.SingleOrDefaultAsync(p => p.Id == existing, ct);
            if (found is null) return Result<Guid>.Invalid("That provider no longer exists.");

            // The scheme is in every callback URL registered with the provider
            // at the far end and in every bookmark. Changing it here would
            // break both, silently, and the operator would find out when
            // sign-in stopped working.
            if (!string.Equals(found.Scheme, draft.Scheme, StringComparison.Ordinal))
                return Result<Guid>.Invalid(
                    "The scheme cannot change — it is in the callback URL registered with the "
                    + "provider. Add a new provider and disable this one instead.");

            provider = found;
            created = false;
        }
        else
        {
            var clash = await _db.IdentityProviders.AnyAsync(
                p => p.Scheme.ToLower() == draft.Scheme.ToLower(), ct);
            if (clash) return Result<Guid>.Invalid($"A provider already uses the scheme \"{draft.Scheme}\".");

            // A new provider with no secret cannot work, and creating one that
            // cannot work is how an operator ends up with a sign-in button that
            // fails at the far end.
            if (string.IsNullOrWhiteSpace(draft.ClientSecret))
                return Result<Guid>.Invalid("A new provider needs its client secret.");

            provider = new IdentityProvider
            {
                Scheme = draft.Scheme.Trim(),
                DisplayName = draft.DisplayName.Trim(),
                ClientId = draft.ClientId.Trim(),
                CreatedByUserId = actor.UserId,
            };
            _db.IdentityProviders.Add(provider);
            created = true;
        }

        var wasEnabled = provider.Enabled;

        provider.Kind = draft.Kind;
        provider.DisplayName = draft.DisplayName.Trim();
        provider.ClientId = draft.ClientId.Trim();
        provider.Authority = Blank(draft.Authority);
        provider.Scopes = Blank(draft.Scopes);
        provider.Enabled = draft.Enabled;
        provider.RequireMfa = draft.RequireMfa;
        provider.UpdatedAt = DateTimeOffset.UtcNow;

        // A blank secret on an EDIT means "leave it alone", not "clear it".
        // Renaming a provider must not require re-typing a secret the operator
        // may no longer have — that is how people end up storing secrets in a
        // second place so they can paste them back.
        if (!string.IsNullOrWhiteSpace(draft.ClientSecret))
            provider.ProtectedClientSecret = _protector.Protect(draft.ClientSecret.Trim());

        _audit.Record(actor,
            created ? "auth_provider.added"
            : wasEnabled != draft.Enabled ? AuditActions.ProviderChanged
            : "auth_provider.updated",
            AuditClass.Access, ScopeTarget.Instance,
            subjectId: provider.Id, subjectKind: nameof(IdentityProvider),
            detail: created
                ? $"{provider.DisplayName} ({provider.Kind}, scheme {provider.Scheme})"
                : wasEnabled != draft.Enabled
                    ? $"{provider.DisplayName} {(draft.Enabled ? "ENABLED" : "DISABLED")}"
                    : $"{provider.DisplayName} updated"
                      + (string.IsNullOrWhiteSpace(draft.ClientSecret) ? "" : " — secret rotated"));

        await _db.SaveChangesAsync(ct);
        return Result<Guid>.Ok(provider.Id);
    }

    /// <summary>
    /// Delete a provider outright.
    ///
    /// Refused while it is the last ENABLED one. An instance with no way in is
    /// recoverable only through the database, and the person who did it is
    /// usually the person who then cannot get back in — the same reasoning that
    /// protects the last instance administrator.
    /// </summary>
    public async Task<Result<bool>> DeleteAsync(
        Principal actor, Guid id, CancellationToken ct = default)
    {
        var decision = _capabilities.Evaluate(actor, Capability.AssignRoles);
        if (!decision.Allowed) return Result<bool>.Denied(decision.Reason!);

        var provider = await _db.IdentityProviders.SingleOrDefaultAsync(p => p.Id == id, ct);
        if (provider is null) return Result<bool>.Ok(false);

        if (provider.Enabled)
        {
            var others = await _db.IdentityProviders.CountAsync(p => p.Enabled && p.Id != id, ct);
            if (others == 0)
                return Result<bool>.Invalid(
                    "This is the only enabled sign-in provider. Removing it would leave no way into "
                    + "the instance, and recovering from that needs database access.");
        }

        _db.IdentityProviders.Remove(provider);

        _audit.Record(actor, "auth_provider.removed", AuditClass.Access, ScopeTarget.Instance,
            subjectId: provider.Id, subjectKind: nameof(IdentityProvider),
            detail: $"{provider.DisplayName} ({provider.Kind}, scheme {provider.Scheme})");

        await _db.SaveChangesAsync(ct);
        return Result<bool>.Ok(true);
    }

    /// <summary>
    /// Everything the host needs to register a scheme, secret included.
    ///
    /// Called only from the authentication layer. It is separate from
    /// <see cref="ListAsync"/> precisely so that the shape carrying a decrypted
    /// secret has exactly one caller, and that caller is not a screen.
    /// </summary>
    public async Task<IReadOnlyList<ProviderConfiguration>> ConfigurationsAsync(
        CancellationToken ct = default)
    {
        var providers = await _db.IdentityProviders.AsNoTracking()
            .Where(p => p.Enabled)
            .ToArrayAsync(ct);

        var configured = new List<ProviderConfiguration>(providers.Length);

        foreach (var provider in providers)
        {
            if (provider.ProtectedClientSecret is not { Length: > 0 } sealed_) continue;

            string secret;
            try
            {
                secret = _protector.Unprotect(sealed_);
            }
            catch (System.Security.Cryptography.CryptographicException)
            {
                // The key that encrypted this is gone — a restored database
                // without its key ring, or a purged key. SKIP the provider
                // rather than registering a handler with an empty secret:
                // an empty ClientSecret makes OAuthOptions.Validate throw on
                // EVERY request, including /health, so one unreadable secret
                // would take the whole instance down.
                continue;
            }

            configured.Add(new ProviderConfiguration(
                provider.Scheme, provider.Kind, provider.DisplayName,
                provider.ClientId, secret, provider.Authority,
                (provider.Scopes ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries),
                provider.RequireMfa));
        }

        return configured;
    }

    /// <summary>Stamp a successful sign-in, so an unused provider is visible.</summary>
    public async Task TouchAsync(string scheme, CancellationToken ct = default)
    {
        var provider = await _db.IdentityProviders
            .SingleOrDefaultAsync(p => p.Scheme == scheme, ct);
        if (provider is null) return;

        provider.LastSignInAt = DateTimeOffset.UtcNow;
        await _db.SaveChangesAsync(ct);
    }

    /// <summary>
    /// May this email register at all?
    ///
    /// Gates REGISTRATION only. Removing a domain must not lock out people who
    /// already have accounts and roles — that is what suspending a user is for,
    /// and doing it as a side effect of a policy edit would be an access change
    /// nobody recorded as one.
    /// </summary>
    public static bool MayRegister(string? email, IReadOnlyCollection<string> allowedDomains)
    {
        if (allowedDomains.Count == 0) return true;
        if (string.IsNullOrWhiteSpace(email)) return false;

        var at = email.LastIndexOf('@');
        if (at < 0 || at == email.Length - 1) return false;

        var domain = email[(at + 1)..];
        return allowedDomains.Any(d => string.Equals(d, domain, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Whether a provider is capable of asserting MFA at all.
    ///
    /// OIDC returns <c>amr</c>; GitHub OAuth returns nothing of the sort. A
    /// requirement against a provider that cannot assert it would be a control
    /// that silently does nothing — worse than no control, because somebody
    /// would believe it.
    /// </summary>
    public static bool CanAssertMfa(IdentityProviderKind kind) => kind == IdentityProviderKind.Oidc;

    private static string? Validate(ProviderDraft draft)
    {
        var scheme = draft.Scheme.Trim();
        if (scheme.Length == 0) return "A provider needs a scheme name.";
        if (!scheme.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_'))
            return "The scheme is a URL segment — letters, digits, hyphen and underscore only.";

        if (draft.DisplayName.Trim().Length == 0)
            return "A provider needs a display name. It is what the sign-in button says.";

        if (draft.ClientId.Trim().Length == 0) return "A provider needs a client id.";

        if (draft.Kind == IdentityProviderKind.Oidc)
        {
            if (string.IsNullOrWhiteSpace(draft.Authority))
                return "An OIDC provider needs its authority — the issuer URL discovery reads from.";
            if (!Uri.TryCreate(draft.Authority.Trim(), UriKind.Absolute, out var authority)
                || authority.Scheme != Uri.UriSchemeHttps)
                return "The authority has to be an https URL. Discovery over http would expose the "
                     + "token endpoint to whoever is between you and the issuer.";
        }

        if (draft.RequireMfa && !CanAssertMfa(draft.Kind))
            return $"{draft.Kind} cannot assert MFA, so requiring it here would be a control that "
                 + "does nothing. Enforce it at the provider instead.";

        return null;
    }

    private static bool Incomplete(
        IdentityProviderKind kind, string clientId, bool hasSecret, string? authority) =>
        string.IsNullOrWhiteSpace(clientId)
        || !hasSecret
        || (kind == IdentityProviderKind.Oidc && string.IsNullOrWhiteSpace(authority));

    private static string? Blank(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}

/// <summary>
/// A provider as the admin screen sees it. NO SECRET, in any form — not even
/// the ciphertext, and not a masked placeholder that a future change might
/// accidentally populate.
/// </summary>
public sealed record ProviderRow(
    Guid Id,
    IdentityProviderKind Kind,
    string Scheme,
    string DisplayName,
    bool Enabled,
    string ClientId,
    string? Authority,
    string? Scopes,
    bool RequireMfa,
    bool HasSecret,
    int UserCount,
    DateTimeOffset? LastSignInAt,
    DateTimeOffset UpdatedAt,
    /// <summary>
    /// Enabled but missing something it needs to run. Worse than being off: the
    /// button is there and the round-trip fails at the far end.
    /// </summary>
    bool Incomplete);

public sealed record ProviderDraft(
    IdentityProviderKind Kind,
    string Scheme,
    string DisplayName,
    string ClientId,
    /// <summary>Blank on an edit means "keep what is stored".</summary>
    string? ClientSecret,
    string? Authority,
    string? Scopes,
    bool Enabled,
    bool RequireMfa);

/// <summary>
/// What the authentication layer needs to register a scheme. Carries the
/// DECRYPTED secret, which is why it is produced by one method with one caller.
/// </summary>
public sealed record ProviderConfiguration(
    string Scheme,
    IdentityProviderKind Kind,
    string DisplayName,
    string ClientId,
    string ClientSecret,
    string? Authority,
    IReadOnlyList<string> Scopes,
    bool RequireMfa);
