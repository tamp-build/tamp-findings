using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Application.Auditing;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Projects;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Application.Attestation;

/// <summary>
/// Freezing an attestation (TFND-103).
///
/// ADR 0001: "an attestation signed in March must be reproducible in September,
/// or the signature attests to nothing." Recomputing does not satisfy that. The
/// policy may have been edited, an advisory feed may have moved, a suppression
/// may have been written — all of which change the answer WITHOUT changing what
/// was true when someone signed.
///
/// So the whole document is stored verbatim and read back verbatim. This class
/// never merges a stored snapshot with fresh data, because a document that is
/// half history and half present is neither.
/// </summary>
public sealed class AttestationSnapshotService
{
    private readonly FindingsDbContext _db;
    private readonly CapabilityEvaluator _capabilities;
    private readonly AuditLog _audit;

    public AttestationSnapshotService(
        FindingsDbContext db, CapabilityEvaluator capabilities, AuditLog audit)
    {
        _db = db;
        _capabilities = capabilities;
        _audit = audit;
    }

    /// <summary>
    /// Freeze the document as generated.
    ///
    /// Capability is <see cref="Capability.ExportAttestation"/>: taking a
    /// snapshot is the act of producing the artefact, and the same people who
    /// may hand the evidence out may fix it in place.
    /// </summary>
    public async Task<Result<Guid>> CaptureAsync(
        Principal actor, ScopeTarget scope, Guid projectId, SsdfAttestationDoc doc,
        CancellationToken ct = default)
    {
        var decision = _capabilities.Evaluate(actor, Capability.ExportAttestation);
        if (!decision.Allowed) return Result<Guid>.Denied(decision.Reason!);

        if (doc.Build is not { } build)
            return Result<Guid>.Invalid("There is no canonical build to attest. Ingest one first.");

        var sha = build.CommitSha is { Length: > 0 } commit ? commit : build.VersionString;

        var snapshot = new AttestationSnapshot
        {
            ProjectId = projectId,
            CommitSha = sha,
            DocumentJson = JsonSerializer.Serialize(doc, SnapshotJson),
            RiskPolicyName = doc.Risk?.PolicyName ?? "(none)",
            Score = doc.Risk?.Score ?? 0,
            Band = doc.Risk?.Band ?? "(none)",
            GeneratedByUserId = actor.UserId,
        };

        // Deliberately NOT deduplicated against an existing snapshot for the
        // same build. Two snapshots of one commit taken a month apart are two
        // different statements about it — the second may reflect a suppression
        // written in between — and collapsing them would erase that.
        _db.AttestationSnapshots.Add(snapshot);

        _audit.Record(actor, "attestation.snapshot", AuditClass.Risk, scope,
            subjectId: snapshot.Id, subjectKind: nameof(AttestationSnapshot),
            detail: $"build {sha} at score {snapshot.Score:0.0} under policy {snapshot.RiskPolicyName}");

        await _db.SaveChangesAsync(ct);
        return Result<Guid>.Ok(snapshot.Id);
    }

    /// <summary>
    /// The newest snapshot for a build, deserialised exactly as stored.
    ///
    /// Returns the DOCUMENT, not a merge of it with anything current. If the
    /// policy has since changed, this still shows the score the old policy
    /// produced — that is the whole point.
    /// </summary>
    public async Task<StoredAttestation?> LatestForBuildAsync(
        Guid projectId, string commitSha, CancellationToken ct = default)
    {
        var snapshot = await _db.AttestationSnapshots.AsNoTracking()
            .Where(s => s.ProjectId == projectId && s.CommitSha == commitSha)
            .OrderByDescending(s => s.GeneratedAt)
            .FirstOrDefaultAsync(ct);

        return snapshot is null ? null : Hydrate(snapshot);
    }

    public async Task<IReadOnlyList<SnapshotRow>> ListAsync(
        Guid projectId, CancellationToken ct = default) =>
        await _db.AttestationSnapshots.AsNoTracking()
            .Where(s => s.ProjectId == projectId)
            .OrderByDescending(s => s.GeneratedAt)
            .Select(s => new SnapshotRow(
                s.Id, s.CommitSha, s.Score, s.Band, s.RiskPolicyName,
                s.GeneratedAt, s.SignedAt, s.SignedBy))
            .ToArrayAsync(ct);

    /// <summary>
    /// Record a signature against a snapshot.
    ///
    /// The signature fields are the ONLY part of a snapshot that may ever
    /// change, and only once — a second signature would overwrite the first and
    /// leave no record that it existed.
    /// </summary>
    public async Task<Result<bool>> SignAsync(
        Principal actor, ScopeTarget scope, Guid projectId, Guid snapshotId, string signatory,
        CancellationToken ct = default)
    {
        var decision = _capabilities.Evaluate(actor, Capability.ExportAttestation);
        if (!decision.Allowed) return Result<bool>.Denied(decision.Reason!);

        signatory = signatory.Trim();
        if (signatory.Length == 0)
            return Result<bool>.Invalid("A signature needs the signatory's name and title.");

        var snapshot = await _db.AttestationSnapshots
            .SingleOrDefaultAsync(s => s.Id == snapshotId && s.ProjectId == projectId, ct);
        if (snapshot is null) return Result<bool>.Invalid("That snapshot no longer exists.");

        if (snapshot.SignedAt is not null)
            return Result<bool>.Invalid($"This snapshot was already signed by {snapshot.SignedBy}.");

        snapshot.SignedAt = DateTimeOffset.UtcNow;
        snapshot.SignedBy = signatory;

        _audit.Record(actor, AuditActions.AttestationSigned, AuditClass.Risk, scope,
            subjectId: snapshot.Id, subjectKind: nameof(AttestationSnapshot),
            detail: $"build {snapshot.CommitSha} signed by {signatory}");

        await _db.SaveChangesAsync(ct);
        return Result<bool>.Ok(true);
    }

    private static StoredAttestation Hydrate(AttestationSnapshot snapshot)
    {
        var doc = JsonSerializer.Deserialize<SsdfAttestationDoc>(snapshot.DocumentJson, SnapshotJson)
                  ?? new SsdfAttestationDoc();

        return new StoredAttestation(
            snapshot.Id, doc, snapshot.GeneratedAt, snapshot.SignedAt, snapshot.SignedBy);
    }

    // Property names are the storage contract for every snapshot ever written.
    // Default (PascalCase) naming, pinned here so a later global JSON
    // convention change cannot make old snapshots unreadable.
    private static readonly JsonSerializerOptions SnapshotJson = new()
    {
        PropertyNamingPolicy = null,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };
}

/// <summary>A snapshot read back: the frozen document plus who signed it.</summary>
public sealed record StoredAttestation(
    Guid Id,
    SsdfAttestationDoc Document,
    DateTimeOffset GeneratedAt,
    DateTimeOffset? SignedAt,
    string? SignedBy);

public sealed record SnapshotRow(
    Guid Id, string CommitSha, double Score, string Band, string RiskPolicyName,
    DateTimeOffset GeneratedAt, DateTimeOffset? SignedAt, string? SignedBy);
