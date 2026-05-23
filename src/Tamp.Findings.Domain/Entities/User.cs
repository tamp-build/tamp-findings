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
    public string? AvatarUrl { get; set; }
    // Set by the admin (or seeded from GITHUB_BOOTSTRAP_ADMIN_LOGIN on the
    // bootstrap user). A signed-in but non-approved user is rejected at the
    // OAuth callback before a session cookie is issued.
    public bool IsApproved { get; set; }
    public bool IsAdmin { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? LastLoginAt { get; set; }
}
