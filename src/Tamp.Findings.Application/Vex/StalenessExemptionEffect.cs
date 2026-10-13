using Tamp.Findings.Application.Approvals;
using Tamp.Findings.Application.Auditing;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Application.Vex;

/// <summary>
/// What an approved SBOM-staleness exemption DOES (TFND-225): creates the VEX
/// statement that stops the component counting against sbomStaleness.
///
/// <para>
/// v1 of this feature (TFND-226) wrote the statement immediately, with no reviewer.
/// That was a deliberate first cut, and the thing wrong with it is what an assessor
/// notices first: a score-lowering override that one person applies to their own
/// project, with nothing recording that anybody else agreed.
/// </para>
/// <para>
/// The mechanism is <see cref="VexPublicationEffect"/>'s, for the same reason — a
/// saved suppressing statement takes effect the moment it exists, so the review
/// cannot be a flag on a stored row. The proposed statement rides on the approval's
/// <see cref="PendingApproval.Payload"/> as a <see cref="VexDraft"/> and only an
/// approval brings it into being. That is also what makes the ticket's requirement
/// fall out for free: until approved there is no statement, so
/// <see cref="Risk.StalenessExemptions"/> does not see it and the component keeps
/// counting, which is the honest state rather than a score that moves on one
/// person's say-so and moves back if the reviewer declines.
/// </para>
/// <para>
/// Unlike publication there is NO direct path: every exemption is a request, an
/// InfoSec officer's own included, because the point is a second person.
/// </para>
/// <para>
/// Runs inside <see cref="ApprovalService.DecideAsync"/>'s transaction on the shared
/// context; never calls SaveChanges (see <see cref="IApprovalEffect"/>).
/// </para>
/// </summary>
public sealed class StalenessExemptionEffect : IApprovalEffect
{
    private readonly FindingsDbContext _db;
    private readonly AuditLog _audit;

    public StalenessExemptionEffect(FindingsDbContext db, AuditLog audit)
    {
        _db = db;
        _audit = audit;
    }

    public ApprovalKind Kind => ApprovalKind.StalenessExemption;

    public async Task ApplyAsync(PendingApproval approval, Principal decider, CancellationToken ct)
    {
        if (ApprovedVexDraft.Read(approval) is not { } draft) return;
        if (approval.ProjectId is not { } projectId) return;

        // An exemption with no justification does not exempt anything —
        // StalenessExemptions.LoadAsync skips Justification None, matching the federal
        // expectation that not_affected always carries a why. Creating one would be a
        // statement that reads as an exemption on the VEX page and silently is not one.
        if (draft.Justification is null or VexJustification.None) return;

        if (await ApprovedVexDraft.ClashesAsync(_db, projectId, draft, ct)) return;

        var statement = ApprovedVexDraft.ToStatement(draft, projectId, approval.RequestedByUserId);
        _db.VexStatements.Add(statement);

        _audit.Record(decider, AuditActions.VexPublished, AuditClass.Risk,
            new ScopeTarget(approval.ClientId, approval.ProjectId),
            subjectId: statement.Id, subjectKind: nameof(VexStatement),
            detail: $"staleness exemption on {statement.Purl}"
                  + (statement.ComponentVersion is { } v ? $" {v}" : " (all versions)")
                  + $" ({statement.Justification}) — approved from a request by {approval.RequestedByLogin}");
    }
}
