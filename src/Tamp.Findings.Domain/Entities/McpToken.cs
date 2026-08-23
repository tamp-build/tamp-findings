using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Domain.Entities;

// A token that lets an AGENT read this instance (TFND-12 / F11.2).
//
// Deliberately NOT an IngestToken with a flag. An ingest token writes evidence
// and reads nothing; this reads evidence and writes nothing. Folding them into
// one row would mean every CI pipeline's token could also read every finding in
// its scope — a silent widening of something that already exists in a hundred
// build configs.
//
// SCOPED DOWN, NEVER UP. A component-level token cannot see its siblings; a
// project-level token sees all its components; a client-level token sees the
// whole tree under that client. The scope is a ScopeTarget, so the same
// resolution a human's roles go through applies unchanged.
public sealed class McpToken
{
    public Guid Id { get; set; } = Guid.NewGuid();

    // Human label. "claude · remediation", "codex · triage". What makes a
    // revoke decision possible six months from now.
    public required string Name { get; set; }

    // The scope this token can see, narrowest tier that is set. Exactly one of
    // these three shapes: client only, client+project, or all three.
    public Guid? ClientId { get; set; }
    public Guid? ProjectId { get; set; }
    public Guid? ComponentId { get; set; }

    // What the agent may DO, expressed as the role it acts as.
    //
    // A role rather than a capability list, so an agent is subject to exactly
    // the matrix a human is — including the parts that matter most, like an
    // agent holding Auditor being able to export and nothing else. Adding a
    // capability to a role automatically applies here, which is the point.
    public ProjectRole? Role { get; set; }

    // SHA-256 hex of the wire token. The plaintext is shown once and is never
    // recoverable — same posture as every other secret in this product.
    public required string TokenHash { get; set; }

    public required Guid CreatedByUserId { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? LastUsedAt { get; set; }

    // Agents are given long-lived credentials and then forgotten about, so
    // these EXPIRE by default. An ingest token that outlives its pipeline is a
    // nuisance; a read token that outlives the agent it was minted for is a
    // standing grant to whatever now holds it.
    public DateTimeOffset? ExpiresAt { get; set; }

    // Soft-delete, so the audit trail survives the revoke.
    public DateTimeOffset? RevokedAt { get; set; }

    /// <summary>Usable right now — not revoked, not expired.</summary>
    public bool IsLive(DateTimeOffset asOf) =>
        RevokedAt is null && (ExpiresAt is null || ExpiresAt > asOf);
}
