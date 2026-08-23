using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Application.Setup;
using Tamp.Findings.Application.SystemAdmin;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Api.Authentication;

/// <summary>
/// What happens after ANY identity provider says who you are (TFND-111).
///
/// Extracted because GitHub OAuth and OIDC differ only in how they fetch a
/// profile. Everything after that — the first-run admin claim, the allowed
/// domain check, the MFA requirement, the approval gate, the claims that go
/// into the cookie — is one policy, and two copies of it would eventually be
/// two policies, with the difference discovered by whoever signed in through
/// the less-maintained one.
/// </summary>
internal static class ExternalSignIn
{
    /// <summary>
    /// A profile, normalised across providers.
    ///
    /// <paramref name="Subject"/> is the provider's stable identifier — a
    /// GitHub numeric id, an OIDC <c>sub</c>. Never the email: people change
    /// email addresses, and an account keyed on one silently becomes a
    /// different account when they do.
    /// </summary>
    internal sealed record Profile(
        string Scheme,
        string Subject,
        string Login,
        string DisplayName,
        string? Email,
        string? AvatarUrl,
        long? GitHubUserId,
        /// <summary>Whether the provider asserted a multi-factor authentication.</summary>
        bool MfaAsserted);

    /// <summary>
    /// The reason a sign-in was refused, or null when it succeeded.
    ///
    /// Returns a REASON rather than throwing, because every one of these ends
    /// as a message on the sign-in page and the caller has to redirect rather
    /// than 500.
    /// </summary>
    internal static async Task<SignInOutcome> ResolveAsync(
        HttpContext http, Profile profile, string? presentedSetupToken, CancellationToken ct)
    {
        var db = http.RequestServices.GetRequiredService<FindingsDbContext>();
        var setup = http.RequestServices.GetRequiredService<SetupToken>();
        var admin = http.RequestServices.GetRequiredService<SystemAdminService>();

        var user = profile.GitHubUserId is { } githubId
            ? await db.Users.FirstOrDefaultAsync(u => u.GitHubUserId == githubId, ct)
            : await db.Users.FirstOrDefaultAsync(
                u => u.ExternalSubject == profile.Subject && u.ExternalScheme == profile.Scheme, ct);

        var settings = await admin.SettingsAsync(ct);

        // FIRST RUN: claiming the administrator seat (TFND-126).
        //
        // The bootstrap for the entire RBAC model. Without it a fresh
        // deployment has no admin, so nobody can approve anyone, grant a role
        // or create a client, and the only way in is editing the database by
        // hand.
        //
        // The check is "no users at all", not "no admins": once anyone exists
        // the instance is in use, and promoting the next arrival would be
        // privilege escalation dressed as convenience.
        var isUnclaimed = user is null && !await db.Users.AnyAsync(ct);

        if (isUnclaimed && !setup.Validate(presentedSetupToken))
        {
            // THE LOAD-BEARING BRANCH. Fail without creating anything.
            //
            // Writing a user row here — even an unapproved one — would consume
            // the "no users exist" condition and permanently break the
            // bootstrap, leaving an instance nobody can administer. That is the
            // difference between a setup token and a speed bump, so this
            // returns before the upsert rather than after.
            http.RequestServices.GetRequiredService<ILoggerFactory>()
                .CreateLogger("Tamp.Findings.Setup")
                .LogWarning(
                    "Rejected an admin claim for {Login} via {Scheme}: setup token missing or wrong. "
                    + "No account created.",
                    profile.Login, profile.Scheme);

            return SignInOutcome.Refused("setup_token");
        }

        // The allowed-domain policy gates REGISTRATION only. Removing a domain
        // must not lock out people who already have accounts and roles — that
        // is what suspending a user is for, and doing it as a side effect of a
        // policy edit would be an access change nobody recorded as one.
        if (user is null && !IdentityProviderService.MayRegister(profile.Email, settings.AllowedEmailDomains))
        {
            return SignInOutcome.Refused("domain_not_allowed");
        }

        var isFirstUser = isUnclaimed;

        if (user is null)
        {
            user = new User
            {
                Login = profile.Login,
                DisplayName = profile.DisplayName,
                Email = profile.Email,
                GitHubUserId = profile.GitHubUserId,
                AvatarUrl = profile.AvatarUrl,
                ExternalScheme = profile.GitHubUserId is null ? profile.Scheme : null,
                ExternalSubject = profile.GitHubUserId is null ? profile.Subject : null,
                IsApproved = isFirstUser,
                IsAdmin = isFirstUser,
            };
            db.Users.Add(user);
        }
        else
        {
            user.Login = profile.Login;
            user.DisplayName = profile.DisplayName;
            user.Email = profile.Email ?? user.Email;
            user.AvatarUrl = profile.AvatarUrl ?? user.AvatarUrl;
        }

        user.LastLoginAt = DateTimeOffset.UtcNow;
        await db.SaveChangesAsync(ct);

        // The seat is claimed. Disarm immediately so the token stops working
        // and stops being printed on the next restart — a claim token that
        // outlives the claim is just a standing credential.
        if (isFirstUser) setup.Claim();

        if (!user.IsApproved) return SignInOutcome.Refused("not_approved");

        // MFA, checked AFTER the user is known because the requirement is per
        // ROLE and roles are on the row. A provider that cannot assert MFA can
        // never satisfy this — which is why the registry refuses to let one be
        // marked as requiring it, and why reaching here means the provider
        // could have asserted it and did not.
        if (await RequiresMfaAsync(db, user, settings.MfaRequiredRoles, ct) && !profile.MfaAsserted)
        {
            return SignInOutcome.Refused("mfa_required");
        }

        await http.RequestServices.GetRequiredService<IdentityProviderService>()
            .TouchAsync(profile.Scheme, ct);

        // Wipe the placeholder identity the handler built and replace it with
        // one we control — keeps the cookie minimal: no upstream access token,
        // no scattered provider-specific claims.
        var identity = new ClaimsIdentity(profile.Scheme);
        identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()));
        identity.AddClaim(new Claim(ClaimTypes.Name, user.Login));
        identity.AddClaim(new Claim(AuthExtensions.TampUserIdClaim, user.Id.ToString()));
        identity.AddClaim(new Claim(AuthExtensions.TampIsAdminClaim, user.IsAdmin.ToString()));
        if (!string.IsNullOrEmpty(user.Email))
            identity.AddClaim(new Claim(ClaimTypes.Email, user.Email));

        return SignInOutcome.Allowed(new ClaimsPrincipal(identity));
    }

    /// <summary>
    /// Does this user hold a role that requires MFA?
    ///
    /// "Admin" is checked against the instance flag rather than a
    /// ProjectRoleAssignment, because it is not a ProjectRole — the same
    /// distinction the RBAC screen makes.
    /// </summary>
    private static async Task<bool> RequiresMfaAsync(
        FindingsDbContext db, User user, IReadOnlyCollection<string> required, CancellationToken ct)
    {
        if (required.Count == 0) return false;

        if (user.IsAdmin && required.Contains("Admin", StringComparer.OrdinalIgnoreCase)) return true;

        var roles = await db.ProjectRoleAssignments.AsNoTracking()
            .Where(a => a.UserId == user.Id)
            .Select(a => a.Role)
            .Distinct()
            .ToArrayAsync(ct);

        return roles.Any(r => required.Contains(r.ToString(), StringComparer.OrdinalIgnoreCase));
    }
}

/// <summary>
/// Whether the sign-in may proceed, and why not when it may not.
///
/// A record rather than an exception because every refusal ends as a message
/// on the sign-in page: the caller redirects, it does not 500.
/// </summary>
internal sealed record SignInOutcome(System.Security.Claims.ClaimsPrincipal? Principal, string? Reason)
{
    internal static SignInOutcome Allowed(System.Security.Claims.ClaimsPrincipal principal) =>
        new(principal, null);

    internal static SignInOutcome Refused(string reason) => new(null, reason);

    internal bool Ok => Principal is not null;
}
