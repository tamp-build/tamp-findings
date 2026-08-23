namespace Tamp.Findings.Domain.Entities;

public sealed class User
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public required string Login { get; set; }
    public required string DisplayName { get; set; }
    public string? Email { get; set; }
    // Stable identifier from GitHub. Login can change; this can't. Null on
    // rows created before TFND-4 OIDC landed.
    public long? GitHubUserId { get; set; }

    // Identity from a registry-configured provider (TFND-111).
    //
    // Separate from GitHubUserId rather than replacing it: the existing rows
    // are keyed on the GitHub id, and rewriting them into a generic pair at
    // migration time would risk re-keying somebody's account onto a subject
    // that turns out not to match.
    //
    // The pair is (scheme, subject) because a subject is only unique WITHIN an
    // issuer. Two OIDC providers can both hand out "1" and mean different
    // people.
    public string? ExternalScheme { get; set; }
    public string? ExternalSubject { get; set; }
    public string? AvatarUrl { get; set; }
    // Set by the admin (or seeded from GITHUB_BOOTSTRAP_ADMIN_LOGIN on the
    // bootstrap user). A signed-in but non-approved user is rejected at the
    // OAuth callback before a session cookie is issued.
    public bool IsApproved { get; set; }
    public bool IsAdmin { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? LastLoginAt { get; set; }
}
