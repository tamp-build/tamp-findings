using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Application.Auditing;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Ingest;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Application.Projects;

/// <summary>
/// The project's ingest key — the credential CI uses to POST scanner output.
///
/// Recycling is the interesting operation, and the design is blunt about why:
///
///   "Recycling invalidates the old key immediately. Any pipeline still using
///    it fails its next ingest, and a missing scan is not a clean scan — the
///    affected builds will read as unscanned."
///
/// That last clause is the real hazard. A broken pipeline does not announce
/// itself; it just stops producing receipts, and the gates then read UNKNOWN
/// on every build until someone notices. TFND-124 adds an optional grace
/// period to remove the hazard entirely.
/// </summary>
public sealed class ProjectKeyService
{
    private readonly FindingsDbContext _db;
    private readonly IngestTokenService _tokens;
    private readonly CapabilityEvaluator _capabilities;
    private readonly AuditLog _audit;

    public ProjectKeyService(
        FindingsDbContext db,
        IngestTokenService tokens,
        CapabilityEvaluator capabilities,
        AuditLog audit)
    {
        _db = db;
        _tokens = tokens;
        _capabilities = capabilities;
        _audit = audit;
    }

    /// <summary>
    /// What the screen can safely show: a masked hint, never the key.
    ///
    /// The plaintext is not stored — only a hash — so this genuinely cannot
    /// return it. That is the property that makes "reveal exactly once"
    /// honest rather than a UI convention.
    /// </summary>
    public async Task<ProjectKeyInfo?> CurrentAsync(Guid projectId, CancellationToken ct = default)
    {
        var token = await _db.IngestTokens.AsNoTracking()
            .Where(t => t.ProjectId == projectId && t.Scope == IngestTokenScope.Project && t.RevokedAt == null)
            .OrderByDescending(t => t.CreatedAt)
            .FirstOrDefaultAsync(ct);

        return token is null ? null : new ProjectKeyInfo(token.Name, token.CreatedAt, token.LastUsedAt);
    }

    /// <summary>
    /// Revoke the current key and mint a replacement.
    ///
    /// Returns the plaintext ONCE. It is never stored and never retrievable —
    /// the caller shows it in a copy-once panel and that is the only chance
    /// anyone gets.
    /// </summary>
    public async Task<Result<string>> RecycleAsync(
        Principal actor, ScopeTarget scope, Guid projectId, CancellationToken ct = default)
    {
        var decision = _capabilities.Evaluate(actor, Capability.ManageIngestKey);
        if (!decision.Allowed) return Result<string>.Denied(decision.Reason!);

        var now = DateTimeOffset.UtcNow;

        var existing = await _db.IngestTokens
            .Where(t => t.ProjectId == projectId && t.Scope == IngestTokenScope.Project && t.RevokedAt == null)
            .ToArrayAsync(ct);

        foreach (var token in existing) token.RevokedAt = now;

        var minted = await _tokens.MintProjectTokenAsync(
            projectId, $"project key ({now:yyyy-MM-dd})", actor.UserId, ct);

        // Access class: this changes who can write to the project, which is
        // one of the three things "an assessor reads first".
        _audit.Record(actor, AuditActions.IngestKeyRecycled, AuditClass.Access, scope,
            subjectId: minted.Record.Id, subjectKind: nameof(IngestToken),
            detail: existing.Length == 0
                ? "First project key issued."
                : $"Replaced {existing.Length} key{(existing.Length == 1 ? "" : "s")}; the previous key stopped working immediately.");

        await _db.SaveChangesAsync(ct);

        return Result<string>.Ok(minted.Plaintext);
    }
}

/// <summary>
/// What is safe to render. Deliberately carries no key material — not even a
/// prefix — because a "hint" is where a leak starts.
/// </summary>
public sealed record ProjectKeyInfo(string Name, DateTimeOffset CreatedAt, DateTimeOffset? LastUsedAt);
