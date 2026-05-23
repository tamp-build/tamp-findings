namespace Tamp.Findings.Domain.Entities;

public enum IngestTokenScope { Client, Project }

// Bearer token used by CI emitters (and eventually the MCP server) to
// authenticate at /ingest/*. Wire format: cli_<43-base64url> or
// prj_<43-base64url>. Only the SHA-256 hex of the full string is
// persisted; plaintext is shown to the operator exactly once at mint
// time and never recoverable from the DB.
public sealed class IngestToken
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public required IngestTokenScope Scope { get; set; }

    // Set when Scope=Client. Authorizes ingest for any project under
    // this client.
    public Guid? ClientId { get; set; }
    // Set when Scope=Project. Authorizes ingest for exactly this project.
    public Guid? ProjectId { get; set; }

    // SHA-256 hex of the wire token (including the cli_/prj_ prefix).
    public required string TokenHash { get; set; }

    // Human label so the operator can identify what a token is for
    // (e.g. "ci · brewerybot", "laptop · scott").
    public required string Name { get; set; }

    public required Guid CreatedByUserId { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? LastUsedAt { get; set; }
    // Soft-delete: revoked tokens stay in the DB so the audit trail isn't
    // lost. RevokedAt non-null → token rejected by Validate.
    public DateTimeOffset? RevokedAt { get; set; }
}
