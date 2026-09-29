using System.Text;
using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Application.Approvals;
using Tamp.Findings.Application.Auditing;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Provenance;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Application.Attestation;

/// <summary>
/// What an approved attestation sign-off request DOES (TFND-123): signs the
/// frozen snapshot.
///
/// <para>
/// The signature is the APPROVER's act — they are the second person putting their
/// name to the frozen document. So the signatory is the approver's, taken from
/// the decision note they entered (their name and title), falling back to their
/// login. The body mirrors <see cref="AttestationSnapshotService.SignAsync"/>:
/// the same allowlisted columns (SignedAt, SignedBy, and, when a key is
/// configured, Signature/SignatureAlgorithm/SigningKeyId) that the immutability
/// guard permits on a frozen snapshot.
/// </para>
/// <para>
/// Runs inside <see cref="ApprovalService.DecideAsync"/>'s transaction on the
/// shared, TRACKED context (the columns must commit with the decision); never
/// calls SaveChanges (see <see cref="IApprovalEffect"/>).
/// </para>
/// </summary>
public sealed class AttestationSignOffEffect : IApprovalEffect
{
    private readonly FindingsDbContext _db;
    private readonly AuditLog _audit;
    private readonly AttestationSigner _signer;

    public AttestationSignOffEffect(FindingsDbContext db, AuditLog audit, AttestationSigner signer)
    {
        _db = db;
        _audit = audit;
        _signer = signer;
    }

    public ApprovalKind Kind => ApprovalKind.AttestationSignOff;

    public async Task ApplyAsync(PendingApproval approval, Principal decider, CancellationToken ct)
    {
        var snapshot = await _db.AttestationSnapshots
            .SingleOrDefaultAsync(s => s.Id == approval.SubjectId, ct);
        // Gone, or already signed by someone (a snapshot takes one signature).
        if (snapshot is null || snapshot.SignedAt is not null) return;

        // The approver is the signatory. Their name and title come from the
        // decision note; a bare login is the honest fallback when they typed none.
        var signatory = string.IsNullOrWhiteSpace(approval.DecisionNote)
            ? decider.Login
            : approval.DecisionNote.Trim();

        snapshot.SignedAt = DateTimeOffset.UtcNow;
        snapshot.SignedBy = signatory;

        if (_signer.CanSign)
        {
            snapshot.Signature = _signer.Sign(Encoding.UTF8.GetBytes(snapshot.DocumentJson));
            snapshot.SignatureAlgorithm = _signer.Algorithm;
            snapshot.SigningKeyId = _signer.KeyId;
        }

        _audit.Record(decider, AuditActions.AttestationSigned, AuditClass.Risk,
            new ScopeTarget(approval.ClientId, approval.ProjectId),
            subjectId: snapshot.Id, subjectKind: nameof(AttestationSnapshot),
            detail: $"build {snapshot.CommitSha} signed by {signatory} — approved sign-off request "
                  + $"from {approval.RequestedByLogin}"
                  + (_signer.CanSign ? $"; key-backed ({_signer.Algorithm}, key {_signer.KeyId?[..12]})" : "; no signing key configured"));
    }
}
