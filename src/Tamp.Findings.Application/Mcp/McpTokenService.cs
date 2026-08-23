using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Application.Auditing;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Projects;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Application.Mcp;

/// <summary>
/// Tokens that let an agent read this instance (TFND-12 / F11.2, F11.4).
///
/// The scoping rule from the epic, and it is the whole design: tokens are
/// scoped DOWN, never up. A component-level token cannot see its siblings; a
/// project-level token sees all its components; a client-level token sees the
/// whole tree under that client.
///
/// That is enforced by resolving the token to a <see cref="Principal"/> at its
/// own <see cref="ScopeTarget"/> and letting the ordinary capability evaluator
/// answer — an agent is subject to exactly the matrix a human is. A second
/// authorization path for agents would be a second place to get it wrong, and
/// the one nobody watches.
/// </summary>
public sealed class McpTokenService
{
    private readonly FindingsDbContext _db;
    private readonly CapabilityEvaluator _capabilities;
    private readonly AuditLog _audit;

    /// <summary>
    /// Wire prefix. Distinct from the ingest prefixes (cli_ / prj_) so a token
    /// pasted into the wrong place fails at the door rather than being tried
    /// against a lookup it can never match.
    /// </summary>
    public const string Prefix = "mcp_";

    public McpTokenService(FindingsDbContext db, CapabilityEvaluator capabilities, AuditLog audit)
    {
        _db = db;
        _capabilities = capabilities;
        _audit = audit;
    }

    public async Task<IReadOnlyList<McpTokenRow>> ListAsync(
        ScopeTarget scope, DateTimeOffset asOf, CancellationToken ct = default)
    {
        // Tokens AT this scope or NARROWER. A project's settings screen should
        // show the component-scoped tokens under it — they read its data — and
        // must not show the client-scoped one, which is somebody else's to
        // manage.
        var tokens = await _db.McpTokens.AsNoTracking()
            .Where(t => t.ClientId == scope.ClientId
                     && (scope.ProjectId == null || t.ProjectId == scope.ProjectId))
            .ToArrayAsync(ct);

        var authors = await _db.Users.AsNoTracking()
            .Where(u => tokens.Select(t => t.CreatedByUserId).Contains(u.Id))
            .Select(u => new { u.Id, u.DisplayName })
            .ToArrayAsync(ct);
        var names = authors.ToDictionary(a => a.Id, a => a.DisplayName);

        return tokens
            .Select(t => new McpTokenRow(
                t.Id, t.Name, Tier(t), t.Role,
                names.TryGetValue(t.CreatedByUserId, out var name) ? name : "(unknown)",
                t.CreatedAt, t.LastUsedAt, t.ExpiresAt, t.RevokedAt,
                t.IsLive(asOf),
                // An agent token nobody has used is either a forgotten
                // credential or a broken integration, and both want seeing.
                t.LastUsedAt is null && t.RevokedAt is null && (asOf - t.CreatedAt).TotalDays > 7))
            .OrderBy(t => !t.Live)
            .ThenByDescending(t => t.CreatedAt)
            .ToArray();
    }

    /// <summary>
    /// Mint a token. The plaintext comes back once and is never recoverable.
    /// </summary>
    public async Task<Result<MintedMcpToken>> MintAsync(
        Principal actor, ScopeTarget scope, string name, ProjectRole? role, int? expiresInDays,
        CancellationToken ct = default)
    {
        // Minting a read token for an agent is granting access, so it needs the
        // capability that grants access — not the one that manages CI keys. An
        // agent token is a standing grant to whatever holds it.
        var decision = _capabilities.Evaluate(actor, Capability.AssignRoles);
        if (!decision.Allowed) return Result<MintedMcpToken>.Denied(decision.Reason!);

        name = name.Trim();
        if (name.Length == 0)
            return Result<MintedMcpToken>.Invalid(
                "A token needs a label — \"claude · remediation\" is what makes a revoke decision "
                + "possible six months from now.");

        if (scope.ClientId is null)
            return Result<MintedMcpToken>.Invalid(
                "An agent token has to be scoped to at least a client. An instance-wide read token "
                + "would be a standing grant over every tenant.");

        // An agent cannot be granted more than the person minting it holds.
        // Otherwise "give the bot Admin" becomes the way anyone escalates.
        if (role is { } wanted && !HoldsAtLeast(actor, wanted))
        {
            return Result<MintedMcpToken>.Invalid(
                $"You do not hold {wanted} at this scope, so you cannot mint a token that does. "
                + "An agent is not a way to grant yourself access.");
        }

        if (expiresInDays is < 1)
            return Result<MintedMcpToken>.Invalid("An expiry is measured in whole days.");

        // 32 bytes, base64url. The prefix is outside the random part so it is
        // greppable in a log without revealing anything.
        var secret = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var wire = Prefix + secret;

        var token = new McpToken
        {
            Name = name,
            ClientId = scope.ClientId,
            ProjectId = scope.ProjectId,
            ComponentId = scope.ComponentId,
            Role = role,
            TokenHash = Hash(wire),
            CreatedByUserId = actor.UserId,
            // Ninety days by default. Agents are given credentials and then
            // forgotten about, and a read token that outlives the agent it was
            // minted for is a standing grant to whatever now holds it.
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(expiresInDays ?? 90),
        };
        _db.McpTokens.Add(token);

        _audit.Record(actor, "mcp_token.created", AuditClass.Access, scope,
            subjectId: token.Id, subjectKind: nameof(McpToken),
            detail: $"{name} at {Tier(token)} as {role?.ToString() ?? "Viewer"}, "
                  + $"expires {token.ExpiresAt:yyyy-MM-dd}");

        await _db.SaveChangesAsync(ct);
        return Result<MintedMcpToken>.Ok(new MintedMcpToken(token.Id, wire));
    }

    public async Task<Result<bool>> RevokeAsync(
        Principal actor, ScopeTarget scope, Guid tokenId, CancellationToken ct = default)
    {
        var decision = _capabilities.Evaluate(actor, Capability.AssignRoles);
        if (!decision.Allowed) return Result<bool>.Denied(decision.Reason!);

        var token = await _db.McpTokens.SingleOrDefaultAsync(t => t.Id == tokenId, ct);
        if (token is null || token.RevokedAt is not null) return Result<bool>.Ok(false);

        token.RevokedAt = DateTimeOffset.UtcNow;

        _audit.Record(actor, "mcp_token.revoked", AuditClass.Access, scope,
            subjectId: token.Id, subjectKind: nameof(McpToken), detail: token.Name);

        await _db.SaveChangesAsync(ct);
        return Result<bool>.Ok(true);
    }

    /// <summary>
    /// Turn a presented token into the principal and scope it grants, or null.
    ///
    /// The ONE door an agent request comes through. Everything downstream reads
    /// through the ordinary services with this principal, so an agent's read is
    /// subject to the same authorization a human's is.
    /// </summary>
    public async Task<AgentIdentity?> ResolveAsync(
        string? presented, DateTimeOffset asOf, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(presented) || !presented.StartsWith(Prefix, StringComparison.Ordinal))
            return null;

        var hash = Hash(presented.Trim());

        var token = await _db.McpTokens.SingleOrDefaultAsync(t => t.TokenHash == hash, ct);
        if (token is null || !token.IsLive(asOf)) return null;

        // Stamped so an unused token is visible on the management screen. Best
        // effort: a failure to record the timestamp must not fail the read.
        token.LastUsedAt = asOf;
        await _db.SaveChangesAsync(ct);

        var scope = new ScopeTarget(token.ClientId, token.ProjectId, token.ComponentId);

        // Guid.Empty as the user id, and a login that says what this is. An
        // agent is not a person, and an audit entry claiming a human took an
        // action a bot took would be worse than no entry.
        var principal = Principal.For(
            Guid.Empty, $"agent:{token.Name}", isAdmin: false,
            token.Role is { } role ? [role] : []);

        return new AgentIdentity(token.Id, token.Name, principal, scope);
    }

    /// <summary>
    /// Does the minter hold at least this role at this scope?
    ///
    /// Admin holds everything except AcceptRisk, which is an Authorizing
    /// Official decision — and an agent must not be a way around that either.
    /// </summary>
    private static bool HoldsAtLeast(Principal actor, ProjectRole role)
    {
        if (actor.Actors.Contains(Actor.Admin)) return role != ProjectRole.InfoSecOfficer;

        return role switch
        {
            ProjectRole.InfoSecOfficer => actor.Actors.Contains(Actor.InfoSecOfficer),
            ProjectRole.LeadDev => actor.Actors.Contains(Actor.LeadDev),
            ProjectRole.Architect => actor.Actors.Contains(Actor.Architect),
            ProjectRole.Auditor => actor.Actors.Contains(Actor.Auditor)
                                   || actor.Actors.Contains(Actor.InfoSecOfficer),
            _ => false,
        };
    }

    private static string Tier(McpToken token) =>
        token.ComponentId is not null ? "Component"
        : token.ProjectId is not null ? "Project"
        : "Client";

    internal static string Hash(string wire) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(wire)));
}

public sealed record McpTokenRow(
    Guid Id, string Name, string Tier, ProjectRole? Role, string CreatedBy,
    DateTimeOffset CreatedAt, DateTimeOffset? LastUsedAt, DateTimeOffset? ExpiresAt,
    DateTimeOffset? RevokedAt, bool Live,
    /// <summary>Live, older than a week, never presented.</summary>
    bool NeverUsed);

/// <summary>A minted token. <see cref="Plaintext"/> exists for one render.</summary>
public sealed record MintedMcpToken(Guid Id, string Plaintext);

/// <summary>Who an agent is, and what it may see.</summary>
public sealed record AgentIdentity(Guid TokenId, string Name, Principal Principal, ScopeTarget Scope);
