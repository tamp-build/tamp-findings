using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Application.Approvals;
using Tamp.Findings.Application.Auditing;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Application.Vex;

/// <summary>
/// What an approved VEX-publication request DOES (TFND-120): creates the
/// statement, published, so it takes effect on the risk picture.
///
/// <para>
/// "Publishing" a VEX statement in this codebase is not a flag on an existing
/// row — a saved suppressing statement relieves its CVE immediately (see
/// <see cref="Risk.VexResolver"/>). So the two-person control cannot let the
/// statement exist unpublished; instead the PROPOSED statement rides on the
/// approval's <see cref="PendingApproval.Payload"/> as a serialized
/// <see cref="VexDraft"/>, and only an approval brings it into being. The direct
/// publish path (an InfoSec officer saving a suppressing statement) is untouched.
/// </para>
/// <para>
/// The approver holds <see cref="Capability.PublishVex"/> by construction, so the
/// created statement is a published one by a rightful publisher. Runs inside
/// <see cref="ApprovalService.DecideAsync"/>'s transaction on the shared context;
/// never calls SaveChanges (see <see cref="IApprovalEffect"/>).
/// </para>
/// </summary>
public sealed class VexPublicationEffect : IApprovalEffect
{
    private readonly FindingsDbContext _db;
    private readonly AuditLog _audit;

    public VexPublicationEffect(FindingsDbContext db, AuditLog audit)
    {
        _db = db;
        _audit = audit;
    }

    public ApprovalKind Kind => ApprovalKind.VexPublication;

    public async Task ApplyAsync(PendingApproval approval, Principal decider, CancellationToken ct)
    {
        if (approval.Payload is not { Length: > 0 } payload) return;

        VexDraft? draft;
        try { draft = JsonSerializer.Deserialize<VexDraft>(payload); }
        catch (JsonException) { return; }
        if (draft is null || approval.ProjectId is not { } projectId) return;

        // Re-check the uniqueness invariant at decision time: someone may have
        // published a statement for the same CVE/component between the request and
        // the approval. Two answers of record for one CVE is exactly what the
        // clash guard in VexQuery.SaveAsync prevents, so honour it here too rather
        // than create a duplicate.
        var clash = await _db.VexStatements.AnyAsync(
            v => v.ProjectId == projectId
              && v.RetiredAt == null
              && v.AdvisoryId == draft.AdvisoryId
              && v.Purl == draft.Purl
              && v.ComponentVersion == draft.ComponentVersion, ct);
        if (clash) return;

        var statement = new VexStatement
        {
            ProjectId = projectId,
            Purl = draft.Purl.Trim(),
            ComponentVersion = string.IsNullOrWhiteSpace(draft.ComponentVersion) ? null : draft.ComponentVersion.Trim(),
            AdvisoryId = draft.AdvisoryId.Trim(),
            Status = draft.Status,
            Justification = draft.Justification,
            ImpactStatement = string.IsNullOrWhiteSpace(draft.ImpactStatement) ? null : draft.ImpactStatement.Trim(),
            ResponseReferenceUrl = string.IsNullOrWhiteSpace(draft.ResponseReferenceUrl) ? null : draft.ResponseReferenceUrl.Trim(),
            // The statement is the requester's authorship; the approver published it.
            AuthorUserId = approval.RequestedByUserId,
        };
        _db.VexStatements.Add(statement);

        _audit.Record(decider, AuditActions.VexPublished, AuditClass.Risk,
            new ScopeTarget(approval.ClientId, approval.ProjectId, null),
            subjectId: statement.Id, subjectKind: nameof(VexStatement),
            detail: $"{statement.AdvisoryId} on {statement.Purl}: {statement.Status}"
                  + (statement.Justification is { } j and not VexJustification.None ? $" ({j})" : "")
                  + $" — published from a request by {approval.RequestedByLogin}");
    }
}
