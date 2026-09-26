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

    // TFND-124: recycle-with-grace. When a key is recycled, the OLD key is not
    // revoked outright — it is given a grace window so pipelines that still hold
    // it keep working until they redeploy the new one. RevokedAt stays null; the
    // key is valid until this instant, after which Validate rejects it. Null
    // means no grace window applies (a key that was never graced, or the current
    // one). A hard revoke (RevokedAt) still wins immediately, for the case where
    // a key must be killed now rather than eased out.
    public DateTimeOffset? GraceExpiresAt { get; set; }

    // TFND-162: the trust tier for the ingest path — a first-class notion
    // distinct from IsApproved / IsAdmin. An UNTRUSTED contributor's token may
    // ADD findings but never AUTO-CLOSE existing ones, so it cannot silently
    // produce a clean result by omitting or clearing findings. Default false
    // (trusted): a token behaves exactly as before unless minted untrusted.
    public bool Untrusted { get; set; }
}
