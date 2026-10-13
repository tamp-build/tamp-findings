using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Application.Approvals;
using Tamp.Findings.Application.Auditing;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Risk;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Application.Compliance;

/// <summary>
/// What an approved control downgrade DOES (ADR 0015 §5, TFND-219): writes the project
/// assertion with <see cref="ControlAssertion.Overrides"/> set, which is the only way
/// that flag is ever set.
///
/// <para>
/// The authoring endpoint cannot set it — that is the whole design. So a disposition
/// that weakens a stricter default always carries a second person's decision and the
/// audit entry recorded here, and the merge's one exception to harden-only can only be
/// reached through this path.
/// </para>
/// <para>
/// Runs inside <see cref="ApprovalService.DecideAsync"/>'s transaction on the shared
/// context; never calls SaveChanges (see <see cref="IApprovalEffect"/>).
/// </para>
/// </summary>
public sealed class ControlDowngradeEffect(FindingsDbContext db, AuditLog audit) : IApprovalEffect
{
    public ApprovalKind Kind => ApprovalKind.ControlDispositionDowngrade;

    public async Task ApplyAsync(PendingApproval approval, Principal decider, CancellationToken ct)
    {
        if (ControlDowngradeService.Read(approval) is not { } request) return;
        if (approval.ProjectId is not { } projectId) return;

        var project = await db.Projects.FirstOrDefaultAsync(p => p.Id == projectId, ct);
        if (project is null) return;

        var layer = project.PolicyLayer ?? PolicyLayer.Empty();
        var controlId = request.ControlId.Trim();

        // One project-layer assertion per control id, same rule the authoring endpoint
        // follows: re-authoring a control replaces its project claim rather than
        // stacking a second one the merge would have to arbitrate.
        layer.Assertions.RemoveAll(a => a.ControlIds.Contains(controlId));
        layer.Assertions.Add(new ControlAssertion
        {
            Kind = request.Kind,
            ControlIds = [controlId],
            Justification = request.Justification,
            InheritedFrom = string.IsNullOrWhiteSpace(request.InheritedFrom)
                ? null
                : request.InheritedFrom.Trim(),
            Overrides = true,
        });

        project.PolicyLayer = layer;
        // jsonb POCO mutations are not always change-tracked; force the update.
        db.Entry(project).Property(p => p.PolicyLayer).IsModified = true;

        audit.Record(decider, "controldisposition.downgraded", AuditClass.Risk,
            new ScopeTarget(approval.ClientId, approval.ProjectId),
            subjectId: projectId, subjectKind: nameof(Project),
            detail: $"{controlId} → {request.Kind} overriding a stricter default "
                  + $"— approved from a request by {approval.RequestedByLogin}: {request.Justification}");
    }
}
