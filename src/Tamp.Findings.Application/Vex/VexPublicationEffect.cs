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
/// publish path (an InfoSec officer saving a suppressing statement) is untouched —
/// which is the one thing <see cref="StalenessExemptionEffect"/> does differently,
/// since a score-lowering override has to have a second person. Reading the draft,
/// re-checking the clash and building the statement are shared, in
/// <see cref="ApprovedVexDraft"/>.
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
        if (ApprovedVexDraft.Read(approval) is not { } draft) return;
        if (approval.ProjectId is not { } projectId) return;

        if (await ApprovedVexDraft.ClashesAsync(_db, projectId, draft, ct)) return;

        // The approver holds PublishVex by construction, so this is a published
        // statement by a rightful publisher.
        var statement = ApprovedVexDraft.ToStatement(draft, projectId, approval.RequestedByUserId);
        _db.VexStatements.Add(statement);

        _audit.Record(decider, AuditActions.VexPublished, AuditClass.Risk,
            new ScopeTarget(approval.ClientId, approval.ProjectId),
            subjectId: statement.Id, subjectKind: nameof(VexStatement),
            detail: $"{statement.AdvisoryId} on {statement.Purl}: {statement.Status}"
                  + (statement.Justification is { } j and not VexJustification.None ? $" ({j})" : "")
                  + $" — published from a request by {approval.RequestedByLogin}");
    }
}
