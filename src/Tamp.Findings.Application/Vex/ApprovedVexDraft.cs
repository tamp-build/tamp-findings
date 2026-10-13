using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Application.Vex;

/// <summary>
/// Turning an approved request's payload into a VEX statement — the part
/// <see cref="VexPublicationEffect"/> and <see cref="StalenessExemptionEffect"/> share.
///
/// <para>
/// Both exist because a saved suppressing statement takes effect the moment it exists,
/// so neither review can be a flag on a stored row: the proposed statement rides on the
/// approval's <see cref="PendingApproval.Payload"/> and only an approval brings it into
/// being. That makes the reading, the clash re-check and the construction identical, and
/// they belong in one place — a second copy of the clash guard would be a second opinion
/// about when two statements are the same statement, and the whole point of the guard is
/// that there is one answer of record per component.
/// </para>
/// <para>
/// What the two effects keep for themselves is what actually differs: which drafts they
/// refuse, and what the audit entry says.
/// </para>
/// </summary>
internal static class ApprovedVexDraft
{
    /// <summary>
    /// The draft the requester proposed, or null if there is none or it will not parse.
    /// A payload that cannot be read is not an error to throw at the decider: the
    /// decision itself succeeded, and there is simply nothing to create.
    /// </summary>
    public static VexDraft? Read(PendingApproval approval)
    {
        if (approval.Payload is not { Length: > 0 } payload) return null;
        try { return JsonSerializer.Deserialize<VexDraft>(payload); }
        catch (JsonException) { return null; }
    }

    /// <summary>
    /// Whether an active statement already answers for this advisory and component.
    ///
    /// Re-checked at DECISION time, not request time: somebody may have published a
    /// statement for the same CVE or component in between, by either path. Two answers
    /// of record for one component is exactly what VexQuery.SaveAsync's clash guard
    /// prevents, so an approval honours it rather than creating a duplicate.
    /// </summary>
    public static Task<bool> ClashesAsync(
        FindingsDbContext db, Guid projectId, VexDraft draft, CancellationToken ct) =>
        db.VexStatements.AnyAsync(
            v => v.ProjectId == projectId
              && v.RetiredAt == null
              && v.AdvisoryId == draft.AdvisoryId
              && v.Purl == draft.Purl
              && v.ComponentVersion == draft.ComponentVersion, ct);

    /// <summary>
    /// The statement itself. Authorship is the REQUESTER's: they made the claim, and
    /// the approver only let it take effect. Recording the approver as author would
    /// lose who is actually asserting it.
    /// </summary>
    public static VexStatement ToStatement(VexDraft draft, Guid projectId, Guid authorUserId) => new()
    {
        ProjectId = projectId,
        Purl = draft.Purl.Trim(),
        ComponentVersion = Blank(draft.ComponentVersion),
        AdvisoryId = draft.AdvisoryId.Trim(),
        Status = draft.Status,
        Justification = draft.Justification,
        ImpactStatement = Blank(draft.ImpactStatement),
        ResponseReferenceUrl = Blank(draft.ResponseReferenceUrl),
        AuthorUserId = authorUserId,
    };

    private static string? Blank(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}
