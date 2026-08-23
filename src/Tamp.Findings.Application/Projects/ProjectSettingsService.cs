using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Application.Auditing;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Ingest;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Application.Projects;

/// <summary>
/// Project settings: ingest tokens and the disclosure policy
/// (TFND-107 / TFND-108).
///
/// Two very different surfaces sharing a screen, and both are about the same
/// thing: what this project tells the outside world. A token is how CI proves
/// it may write here; a VDP is how a researcher knows where to report.
/// </summary>
public sealed class ProjectSettingsService
{
    private readonly FindingsDbContext _db;
    private readonly CapabilityEvaluator _capabilities;
    private readonly IngestTokenService _tokens;
    private readonly AuditLog _audit;

    public ProjectSettingsService(
        FindingsDbContext db, CapabilityEvaluator capabilities,
        IngestTokenService tokens, AuditLog audit)
    {
        _db = db;
        _capabilities = capabilities;
        _tokens = tokens;
        _audit = audit;
    }

    // ---- Ingest tokens ----------------------------------------------------

    /// <summary>
    /// Tokens for this project, revoked ones included.
    ///
    /// Revoked tokens stay visible because "was this key live in March?" is the
    /// question that gets asked after an incident, and a list that quietly
    /// drops them cannot answer it.
    /// </summary>
    public async Task<IReadOnlyList<TokenRow>> TokensAsync(
        Guid projectId, DateTimeOffset asOf, CancellationToken ct = default)
    {
        var tokens = await _db.IngestTokens.AsNoTracking()
            .Where(t => t.ProjectId == projectId)
            .Select(t => new
            {
                t.Id, t.Name, t.TokenHash, t.CreatedAt, t.LastUsedAt, t.RevokedAt, t.CreatedByUserId,
            })
            .ToArrayAsync(ct);

        var authorIds = tokens.Select(t => t.CreatedByUserId).Distinct().ToArray();
        var authors = await _db.Users.AsNoTracking()
            .Where(u => authorIds.Contains(u.Id))
            .Select(u => new { u.Id, u.DisplayName })
            .ToArrayAsync(ct);
        var names = authors.ToDictionary(a => a.Id, a => a.DisplayName);

        return tokens
            .Select(t => new TokenRow(
                t.Id,
                t.Name,
                // The hash prefix, not the token. It is enough to match a
                // rejected request in a log against a row here, and it is not
                // enough to authenticate with.
                t.TokenHash[..8],
                names.TryGetValue(t.CreatedByUserId, out var name) ? name : "(unknown)",
                t.CreatedAt,
                t.LastUsedAt,
                t.RevokedAt,
                // A token nobody has ever used is worth flagging: either the
                // pipeline that needed it was never wired up, or it was and it
                // is failing silently.
                t.LastUsedAt is null && t.RevokedAt is null && (asOf - t.CreatedAt).TotalDays > 7))
            .OrderBy(t => t.RevokedAt is not null)
            .ThenByDescending(t => t.CreatedAt)
            .ToArray();
    }

    /// <summary>
    /// Mint a token. The plaintext comes back ONCE and is never recoverable.
    /// </summary>
    public async Task<Result<MintedToken>> MintTokenAsync(
        Principal actor, ScopeTarget scope, Guid projectId, string name, CancellationToken ct = default)
    {
        var decision = _capabilities.Evaluate(actor, Capability.ManageIngestKey);
        if (!decision.Allowed) return Result<MintedToken>.Denied(decision.Reason!);

        name = name.Trim();
        if (name.Length == 0)
            return Result<MintedToken>.Invalid(
                "A token needs a label. \"ci · brewerybot\" is what makes a revoke decision possible "
                + "six months from now.");

        var minted = await _tokens.MintProjectTokenAsync(projectId, name, actor.UserId, ct);

        // Access class: a new key is a new way in, and that is what an assessor
        // reads first alongside role grants and risk acceptance.
        _audit.Record(actor, AuditActions.TokenCreated, AuditClass.Access, scope,
            subjectId: minted.Record.Id, subjectKind: nameof(IngestToken), detail: name);

        await _db.SaveChangesAsync(ct);
        return Result<MintedToken>.Ok(minted);
    }

    public async Task<Result<bool>> RevokeTokenAsync(
        Principal actor, ScopeTarget scope, Guid projectId, Guid tokenId, CancellationToken ct = default)
    {
        var decision = _capabilities.Evaluate(actor, Capability.ManageIngestKey);
        if (!decision.Allowed) return Result<bool>.Denied(decision.Reason!);

        var token = await _db.IngestTokens.SingleOrDefaultAsync(
            t => t.Id == tokenId && t.ProjectId == projectId, ct);
        if (token is null) return Result<bool>.Ok(false);
        if (token.RevokedAt is not null) return Result<bool>.Ok(false);

        token.RevokedAt = DateTimeOffset.UtcNow;

        _audit.Record(actor, AuditActions.TokenRevoked, AuditClass.Access, scope,
            subjectId: token.Id, subjectKind: nameof(IngestToken), detail: token.Name);

        await _db.SaveChangesAsync(ct);
        return Result<bool>.Ok(true);
    }

    // ---- Disclosure policy ------------------------------------------------

    /// <summary>
    /// The GitHub repository this project maps to, "owner/name" (TFND-23).
    /// </summary>
    public async Task<string?> RepositoryAsync(Guid projectId, CancellationToken ct = default) =>
        await _db.Projects.AsNoTracking()
            .Where(p => p.Id == projectId)
            .Select(p => p.GitHubRepository)
            .SingleOrDefaultAsync(ct);

    /// <summary>
    /// Map this project to a repository, or unmap it.
    ///
    /// Per project rather than derived from the commit, because a commit sha
    /// says nothing about which repository it came from — the same sha exists
    /// in every fork, and posting a check run to the wrong repository is a
    /// message to somebody else's team.
    /// </summary>
    public async Task<Result<bool>> SaveRepositoryAsync(
        Principal actor, ScopeTarget scope, Guid projectId, string? repository,
        CancellationToken ct = default)
    {
        var decision = _capabilities.Evaluate(actor, Capability.ManageIngestKey);
        if (!decision.Allowed) return Result<bool>.Denied(decision.Reason!);

        var normalised = Normalise(repository);

        if (normalised is not null)
        {
            // "owner/name", nothing else. A full URL, a trailing .git or a
            // branch suffix all produce a 404 from GitHub at publish time,
            // which surfaces as a check that silently never appears.
            var parts = normalised.Split('/');
            if (parts.Length != 2 || parts.Any(string.IsNullOrWhiteSpace))
                return Result<bool>.Invalid("Use owner/name — not a URL, and without a .git suffix.");
        }

        var project = await _db.Projects.SingleOrDefaultAsync(p => p.Id == projectId, ct);
        if (project is null) return Result<bool>.Invalid("That project no longer exists.");

        var before = project.GitHubRepository;
        project.GitHubRepository = normalised;

        // Access class: this decides where this instance writes on somebody
        // else's platform, which is a reach outward rather than housekeeping.
        _audit.Record(actor, "project.github_repository_changed", AuditClass.Access, scope,
            subjectId: project.Id, subjectKind: nameof(Project),
            detail: normalised is null
                ? $"unmapped from {before ?? "(nothing)"}"
                : $"{before ?? "(nothing)"} → {normalised}");

        await _db.SaveChangesAsync(ct);
        return Result<bool>.Ok(true);
    }

    public async Task<VdpSettings?> DisclosureAsync(Guid projectId, CancellationToken ct = default) =>
        await _db.Projects.AsNoTracking()
            .Where(p => p.Id == projectId)
            .Select(p => new VdpSettings(p.VdpPolicyUrl, p.VdpContactEmail, p.VdpReportingFormUrl))
            .SingleOrDefaultAsync(ct);

    /// <summary>
    /// Save the VDP metadata.
    ///
    /// This is not cosmetic: a published policy URL flips SSDF RV.3.1 from
    /// Manual to Yes, and a contact email alone caps it at Partial. Saving a
    /// URL that does not resolve would put a claim in an attestation that
    /// nobody can check, so the shape is validated even though the reachability
    /// cannot be.
    /// </summary>
    public async Task<Result<VdpEffect>> SaveDisclosureAsync(
        Principal actor, ScopeTarget scope, Guid projectId, VdpSettings settings,
        CancellationToken ct = default)
    {
        var decision = _capabilities.Evaluate(actor, Capability.EditDisclosurePolicy);
        if (!decision.Allowed) return Result<VdpEffect>.Denied(decision.Reason!);

        if (Normalise(settings.PolicyUrl) is { } policyUrl && !IsHttpUrl(policyUrl))
            return Result<VdpEffect>.Invalid("The policy URL needs to be a full http or https address.");
        if (Normalise(settings.ReportingFormUrl) is { } formUrl && !IsHttpUrl(formUrl))
            return Result<VdpEffect>.Invalid("The reporting form URL needs to be a full http or https address.");
        if (Normalise(settings.ContactEmail) is { } email && !email.Contains('@'))
            return Result<VdpEffect>.Invalid("The security contact needs to be an email address.");

        var project = await _db.Projects.SingleOrDefaultAsync(p => p.Id == projectId, ct);
        if (project is null) return Result<VdpEffect>.Invalid("That project no longer exists.");

        var before = Effect(new VdpSettings(
            project.VdpPolicyUrl, project.VdpContactEmail, project.VdpReportingFormUrl));

        project.VdpPolicyUrl = Normalise(settings.PolicyUrl);
        project.VdpContactEmail = Normalise(settings.ContactEmail);
        project.VdpReportingFormUrl = Normalise(settings.ReportingFormUrl);

        var after = Effect(settings);

        _audit.Record(actor, "project.vdp_changed",
            // Risk class only when the ATTESTATION ANSWER moves. Editing a
            // contact address is housekeeping; turning RV.3.1 from Manual to
            // Yes changes what a signed document claims.
            before == after ? AuditClass.Other : AuditClass.Risk,
            scope,
            subjectId: project.Id, subjectKind: nameof(Project),
            detail: before == after ? "VDP details updated" : $"SSDF RV.3.1 {before} → {after}");

        await _db.SaveChangesAsync(ct);
        return Result<VdpEffect>.Ok(after);
    }

    /// <summary>
    /// What the current VDP metadata does to SSDF RV.3.1.
    ///
    /// Mirrors SsdfAttestationBuilder's own rule so the settings screen can say
    /// what the attestation will say. Two different answers on two screens is
    /// how a team learns to trust neither.
    /// </summary>
    public static VdpEffect Effect(VdpSettings settings)
    {
        if (!string.IsNullOrWhiteSpace(settings.PolicyUrl)) return VdpEffect.Yes;
        if (!string.IsNullOrWhiteSpace(settings.ContactEmail)) return VdpEffect.Partial;
        return VdpEffect.No;
    }

    private static string? Normalise(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    private static bool IsHttpUrl(string value) =>
        Uri.TryCreate(value, UriKind.Absolute, out var uri)
        && (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps);
}

public sealed record TokenRow(
    Guid Id,
    string Name,
    string HashPrefix,
    string CreatedBy,
    DateTimeOffset CreatedAt,
    DateTimeOffset? LastUsedAt,
    DateTimeOffset? RevokedAt,
    /// <summary>
    /// Live, older than a week, and never used. Either the pipeline was never
    /// wired up or it is failing silently — both worth knowing.
    /// </summary>
    bool NeverUsed)
{
    public bool Revoked => RevokedAt is not null;
}

public sealed record VdpSettings(string? PolicyUrl, string? ContactEmail, string? ReportingFormUrl);

/// <summary>What the VDP metadata makes SSDF RV.3.1 answer.</summary>
public enum VdpEffect { No, Partial, Yes }
