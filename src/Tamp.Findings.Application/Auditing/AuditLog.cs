using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Application.Auditing;

/// <summary>
/// The write path for the audit trail.
///
/// Lives in Application, next to the authorization it records, so an action
/// cannot be performed through a route that forgets to audit it — the same
/// reasoning ADR 0002 gives for putting authorization here. A transport can
/// forget; the layer beneath it cannot.
/// </summary>
public sealed class AuditLog
{
    private readonly FindingsDbContext _db;

    public AuditLog(FindingsDbContext db) => _db = db;

    /// <summary>
    /// Record an action. Does NOT save — the entry is added to the same
    /// transaction as the change it describes, so an audit entry can never
    /// survive a rolled-back action, and an action can never commit without
    /// its entry.
    /// </summary>
    public AuditEntry Record(
        Principal actor,
        string action,
        AuditClass @class,
        ScopeTarget scope = default,
        Guid? subjectId = null,
        string? subjectKind = null,
        string? detail = null)
    {
        ArgumentNullException.ThrowIfNull(actor);
        ArgumentException.ThrowIfNullOrWhiteSpace(action);

        var entry = new AuditEntry
        {
            UserId = actor.UserId == Guid.Empty ? null : actor.UserId,
            ActorLogin = actor.Login,
            ActorRole = MostSeniorRole(actor),
            ActorWasAdmin = actor.Actors.Contains(Actor.Admin),
            Action = action,
            Class = @class,
            ClientId = scope.ClientId,
            ProjectId = scope.ProjectId,
            ComponentId = scope.ComponentId,
            SubjectId = subjectId,
            SubjectKind = subjectKind,
            Detail = detail,
        };

        _db.AuditEntries.Add(entry);
        return entry;
    }

    /// <summary>
    /// Record an ingest, attributed to the bearer token that authenticated it.
    ///
    /// Ingest has no user identity yet (that is TFND-161 — identity-bound
    /// ingest), so the actor is the token: <c>ActorLogin</c> carries the
    /// operator-set token label and the token id is the subject, so an assessor
    /// can answer "which credential posted this" and revoke it. When
    /// identity-bound ingest lands, this grows a real <see cref="Principal"/>
    /// and the token becomes corroborating detail rather than the actor.
    /// </summary>
    public AuditEntry RecordIngest(
        Guid tokenId,
        string tokenLabel,
        Guid? actorUserId,
        string? actorLogin,
        string action,
        ScopeTarget scope = default,
        string? detail = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(action);

        // TFND-161: identity-bound ingest. When the bearer token's minting user
        // is known, the ingest is attributed to that PERSON (real login + user
        // id), with the token recorded as the subject and named in the detail —
        // so an assessor can answer "who posted this scan", not just "some
        // token did". Falls back to the token label only when the user is gone.
        var entry = new AuditEntry
        {
            UserId = actorUserId,
            ActorLogin = actorLogin ?? $"token:{tokenLabel}",
            Action = action,
            Class = AuditClass.Other,
            ClientId = scope.ClientId,
            ProjectId = scope.ProjectId,
            ComponentId = scope.ComponentId,
            SubjectId = tokenId,
            SubjectKind = "ingest_token",
            Detail = actorLogin is null || detail is null ? detail : $"via token '{tokenLabel}': {detail}",
        };

        _db.AuditEntries.Add(entry);
        return entry;
    }

    /// <summary>Record something the system did on nobody's behalf — a scheduled workflow, an ingest.</summary>
    public AuditEntry RecordSystem(
        string action,
        AuditClass @class,
        ScopeTarget scope = default,
        Guid? subjectId = null,
        string? subjectKind = null,
        string? detail = null)
    {
        var entry = new AuditEntry
        {
            UserId = null,
            ActorLogin = "system",
            Action = action,
            Class = @class,
            ClientId = scope.ClientId,
            ProjectId = scope.ProjectId,
            ComponentId = scope.ComponentId,
            SubjectId = subjectId,
            SubjectKind = subjectKind,
            Detail = detail,
        };

        _db.AuditEntries.Add(entry);
        return entry;
    }

    /// <summary>
    /// Read the trail. Newest first — an assessor starts from "what happened
    /// recently" and narrows from there.
    /// </summary>
    public async Task<IReadOnlyList<AuditEntry>> QueryAsync(
        AuditClass? @class = null,
        Guid? clientId = null,
        Guid? projectId = null,
        string? actorLogin = null,
        DateTimeOffset? since = null,
        DateTimeOffset? until = null,
        int take = 200,
        CancellationToken ct = default)
    {
        var q = _db.AuditEntries.AsNoTracking().AsQueryable();

        if (@class is { } c) q = q.Where(e => e.Class == c);
        if (clientId is { } cl) q = q.Where(e => e.ClientId == cl);
        if (projectId is { } pr) q = q.Where(e => e.ProjectId == pr);
        if (!string.IsNullOrWhiteSpace(actorLogin)) q = q.Where(e => e.ActorLogin == actorLogin);
        if (since is { } s) q = q.Where(e => e.At >= s);
        if (until is { } u) q = q.Where(e => e.At <= u);

        return await q.OrderByDescending(e => e.At)
                      .Take(Math.Clamp(take, 1, 1000))
                      .ToArrayAsync(ct);
    }

    // The authority the actor acted under. With additive roles a person may
    // hold several, so record the most senior one that could have authorised
    // the act — plus the admin flag separately, since Admin is not a
    // ProjectRole and an admin acting is a materially different fact.
    private static ProjectRole? MostSeniorRole(Principal actor) =>
        actor.Actors.Contains(Actor.InfoSecOfficer) ? ProjectRole.InfoSecOfficer
        : actor.Actors.Contains(Actor.Architect) ? ProjectRole.Architect
        : actor.Actors.Contains(Actor.LeadDev) ? ProjectRole.LeadDev
        : actor.Actors.Contains(Actor.Auditor) ? ProjectRole.Auditor
        : null;
}

/// <summary>
/// Stable action keys.
///
/// Dotted and machine-readable rather than sentences: filters, exports and any
/// future OSCAL mapping key off these, and prose belongs in Detail. Adding a
/// key is fine; changing one silently reclassifies history.
/// </summary>
public static class AuditActions
{
    // Risk — a human decision that moved the risk posture.
    public const string PoamRiskAccepted = "poam.risk_accepted";
    public const string PoamCompleted = "poam.completed";
    public const string PoamExtensionRequested = "poam.extension_requested";
    public const string PoamDeleted = "poam.deleted";
    public const string SuppressionAuthored = "suppression.authored";
    public const string VexPublished = "vex.published";
    public const string PolicySaved = "policy.saved";
    public const string GateChanged = "gate.changed";
    // Three-layer policy (ADR 0007).
    public const string PolicyTemplateSaved = "policy_template.saved";
    public const string PolicyTemplateLoosened = "policy_template.loosened";
    public const string ClientPolicySaved = "client_policy.saved";
    public const string ClientTemplateSwitched = "client.template_switched";
    public const string ComplianceProfileRead = "compliance_profile.read";
    public const string ConformanceIngested = "conformance.ingested";

    // Access — who can do what changed.
    // The two bootstrap paths to administrator — the single most privileged,
    // once-only transition on the instance, and the root of the access-control
    // trust chain an assessor reads first (TFND-140).
    public const string AdminSeatClaimed = "admin.seat_claimed";
    public const string AdminBootstrapPromoted = "admin.bootstrap_promoted";
    public const string RoleGranted = "role.granted";
    public const string RoleRevoked = "role.revoked";
    public const string IngestKeyRecycled = "ingest_key.recycled";
    public const string TokenCreated = "token.created";
    public const string TokenRevoked = "token.revoked";
    public const string ProviderChanged = "auth_provider.changed";

    // Other.
    public const string AttestationExported = "attestation.exported";
    public const string AttestationSigned = "attestation.signed";

    // Ingest — a build posted evidence. Machine, not a human decision, so
    // AuditClass.Other; attributed to the bearer token (see RecordIngest).
    // Traceability seam for TFND-142; the auto-close case is the one that can
    // silently retire real findings, so it is called out in Detail.
    public const string IngestReceived = "ingest.received";
}
