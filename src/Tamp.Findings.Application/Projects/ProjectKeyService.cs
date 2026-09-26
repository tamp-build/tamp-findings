using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Application.Approvals;
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
    // How long a recycled key's predecessor keeps working. Long enough for a
    // team to notice, redeploy their pipelines and confirm green; short enough
    // that a leaked old key is not valid indefinitely.
    private static readonly TimeSpan GraceWindow = TimeSpan.FromDays(7);

    private readonly FindingsDbContext _db;
    private readonly IngestTokenService _tokens;
    private readonly CapabilityEvaluator _capabilities;
    private readonly AuditLog _audit;
    private readonly ApprovalService _approvals;

    public ProjectKeyService(
        FindingsDbContext db,
        IngestTokenService tokens,
        CapabilityEvaluator capabilities,
        AuditLog audit,
        ApprovalService approvals)
    {
        _db = db;
        _tokens = tokens;
        _capabilities = capabilities;
        _audit = audit;
        _approvals = approvals;
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
    /// Does this instance require a second approver to recycle the key?
    ///
    /// True when separation of duties is enforced: the direct recycle is then
    /// refused and the caller must request one for a different key manager to
    /// approve. The UI reads this to decide which affordance to show; the service
    /// enforces it regardless.
    /// </summary>
    public async Task<bool> RecycleRequiresApprovalAsync(CancellationToken ct = default) =>
        await _db.InstanceSettings.AsNoTracking()
            .Where(s => s.Id == InstanceSettings.SingletonId)
            .Select(s => s.EnforceSeparationOfDuties)
            .FirstOrDefaultAsync(ct);

    /// <summary>
    /// Recycle the key directly: put the old key(s) into a grace window and mint
    /// a replacement (TFND-124).
    ///
    /// <para>
    /// The old key keeps working for <see cref="GraceWindow"/> so a pipeline that
    /// still holds it does not fail its next ingest — a broken pipeline reads as
    /// UNKNOWN on every build until someone notices, which is the hazard this
    /// removes.
    /// </para>
    /// <para>
    /// Refused when separation of duties is enforced: recycle then needs a second
    /// person, so the caller is steered to request one. Returns the plaintext
    /// ONCE — never stored, never retrievable.
    /// </para>
    /// </summary>
    public async Task<Result<string>> RecycleAsync(
        Principal actor, ScopeTarget scope, Guid projectId, CancellationToken ct = default)
    {
        var decision = _capabilities.Evaluate(actor, Capability.ManageIngestKey);
        if (!decision.Allowed) return Result<string>.Denied(decision.Reason!);

        if (await RecycleRequiresApprovalAsync(ct))
            return Result<string>.Invalid(
                "This instance requires a second approver to recycle the ingest key. "
                + "Request it instead — a different key manager approves and receives the new key.");

        var plaintext = await GraceAndMintAsync(actor, scope, projectId, ct);
        return Result<string>.Ok(plaintext);
    }

    /// <summary>
    /// Approve a pending recycle request and perform the recycle (TFND-124).
    ///
    /// <para>
    /// Recycle produces a secret that has to reach a human, and an
    /// <c>IApprovalEffect</c> returns nothing — so this kind is completed here
    /// rather than through the generic effect dispatch. The decision goes through
    /// <see cref="ApprovalService.DecideAsync"/> (which owns the self-approval
    /// guard, the decider-capability check and the audit), and on a YES this mints
    /// the new key and returns its plaintext to the APPROVER, who is the key
    /// manager that will deploy it.
    /// </para>
    /// </summary>
    public async Task<Result<string>> ApproveRecycleAsync(
        Principal actor, Guid approvalId, CancellationToken ct = default)
    {
        var decision = await _approvals.DecideAsync(actor, approvalId, approve: true, ct: ct);
        if (!decision.Success)
            return decision.WasDenied
                ? Result<string>.Denied(decision.Error!)
                : Result<string>.Invalid(decision.Error!);

        var approval = await _db.PendingApprovals.AsNoTracking().SingleAsync(a => a.Id == approvalId, ct);
        if (approval.ProjectId is not { } projectId)
            return Result<string>.Invalid("That recycle request is not scoped to a project.");

        var scope = new ScopeTarget(approval.ClientId, approval.ProjectId, null);
        var plaintext = await GraceAndMintAsync(actor, scope, projectId, ct);
        return Result<string>.Ok(plaintext);
    }

    // The shared recycle mechanics: grace the live key(s), mint a replacement,
    // audit, commit. No capability or SoD gate here — the caller has already
    // established the authorization (a direct ManageIngestKey holder, or an
    // approved request).
    private async Task<string> GraceAndMintAsync(
        Principal actor, ScopeTarget scope, Guid projectId, CancellationToken ct)
    {
        var now = DateTimeOffset.UtcNow;
        var graceUntil = now + GraceWindow;

        var existing = await _db.IngestTokens
            .Where(t => t.ProjectId == projectId && t.Scope == IngestTokenScope.Project
                     && t.RevokedAt == null && t.GraceExpiresAt == null)
            .ToArrayAsync(ct);

        foreach (var token in existing) token.GraceExpiresAt = graceUntil;

        var minted = await _tokens.MintProjectTokenAsync(
            projectId, $"project key ({now:yyyy-MM-dd})", actor.UserId, ct);

        // Access class: this changes who can write to the project, which is
        // one of the three things "an assessor reads first".
        _audit.Record(actor, AuditActions.IngestKeyRecycled, AuditClass.Access, scope,
            subjectId: minted.Record.Id, subjectKind: nameof(IngestToken),
            detail: existing.Length == 0
                ? "First project key issued."
                : $"Replaced {existing.Length} key{(existing.Length == 1 ? "" : "s")}; "
                  + $"the previous key{(existing.Length == 1 ? "" : "s")} keep working until "
                  + $"{graceUntil:yyyy-MM-dd}, then stop.");

        await _db.SaveChangesAsync(ct);
        return minted.Plaintext;
    }
}

/// <summary>
/// What is safe to render. Deliberately carries no key material — not even a
/// prefix — because a "hint" is where a leak starts.
/// </summary>
public sealed record ProjectKeyInfo(string Name, DateTimeOffset CreatedAt, DateTimeOffset? LastUsedAt);
