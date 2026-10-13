using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Application.Approvals;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Policy;
using Tamp.Findings.Application.Projects;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Risk;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Application.Compliance;

/// <summary>What a proposed project disposition would weaken, and where that came from.</summary>
public sealed record DowngradeConflict(
    string ControlId,
    ControlDispositionKind Proposed,
    ControlDispositionKind Inherited,
    /// <summary>The layer that asserts the stricter disposition, by its human label.</summary>
    string InheritedSource)
{
    public string Describe() =>
        $"{ControlId}: {Proposed} is weaker than {Inherited} from {InheritedSource}";
}

/// <summary>What an approved downgrade will write. Rides on the approval's payload.</summary>
public sealed record DowngradeRequest(
    string ControlId,
    ControlDispositionKind Kind,
    string Justification,
    string? InheritedFrom);

/// <summary>
/// The review-gated project downgrade (ADR 0015 §5, TFND-219).
///
/// <para>
/// ADR 0015 made the project the authority for control dispositions and left one piece
/// unbuilt. The merge is harden-only, strictest-kind-wins, so a project can fill an
/// Unmapped control or upgrade one to owned freely, and cannot weaken what a template
/// or archetype asserted — that is the "an unscanned control does not pass" guarantee,
/// and it is worth keeping. But a project sometimes genuinely is the authority: an
/// admin determines a control does not apply HERE, over a stricter default.
/// </para>
/// <para>
/// Before this, that determination was accepted by the authoring endpoint, stored on
/// the project layer, and then silently lost the merge. The write returned 200 and
/// changed nothing an operator could see — the coverage view went on showing the
/// default with no indication that somebody had decided otherwise. That is the worst of
/// the three options: worse than refusing, and worse than allowing it.
/// </para>
/// <para>
/// So: the authoring endpoint REFUSES a downgrade and names what it would weaken, and a
/// downgrade is instead requested, approved by someone holding
/// <see cref="Capability.AcceptRisk"/>, and written by
/// <see cref="ControlDowngradeEffect"/> with <see cref="ControlAssertion.Overrides"/>
/// set. ADR 0015 §5 says "the same rule as loosening an acceptance gate", and that rule
/// is <see cref="ApprovalKind.LoosenPolicyTemplate"/>'s: AcceptRisk, which Admin
/// deliberately does not hold even though Admin is who authors dispositions. The ADR
/// also points at ADR 0012's review gate; that gate is a Draft→Reviewed status an admin
/// promotes, which would let the same admin author and bless their own loosening, so it
/// is the weaker reading of the two and not the one taken here.
/// </para>
/// </summary>
public sealed class ControlDowngradeService(
    PolicyResolver policy,
    ApprovalService approvals)
{
    /// <summary>
    /// Which of these proposed dispositions would weaken something a lower layer
    /// asserts. Empty means every one of them is a fill or an upgrade and the ordinary
    /// authoring path can take them.
    /// </summary>
    public async Task<IReadOnlyList<DowngradeConflict>> ConflictsAsync(
        Guid projectId,
        IReadOnlyList<(string ControlId, ControlDispositionKind Kind)> proposed,
        CancellationToken ct = default)
    {
        if (proposed.Count == 0) return [];

        // The INHERITED stack, not the full one: the full stack already contains the
        // project's previous claim for this control, so comparing against it would
        // call a correction of the project's own earlier downgrade a downgrade.
        var inherited = await policy.InheritedForProjectAsync(projectId, ct);

        var conflicts = new List<DowngradeConflict>();
        foreach (var (controlId, kind) in proposed)
        {
            if (!inherited.Assertions.TryGetValue(controlId, out var below)) continue;
            // Strictness ordering: lower enum value is stricter (Gated = 0). Equal is
            // not a downgrade — re-asserting what you inherit is a no-op, not a loosening.
            if ((int)kind > (int)below.Kind)
                conflicts.Add(new DowngradeConflict(controlId, kind, below.Kind, below.Source));
        }
        return conflicts;
    }

    /// <summary>
    /// Ask for a downgrade. One request per control: they are decided on their own
    /// merits, and a reviewer who agrees about one control and not another has to be
    /// able to say so.
    /// </summary>
    public async Task<Result<Guid>> RequestAsync(
        Principal actor, ScopeTarget scope, Guid projectId,
        DowngradeRequest request, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(request.Justification))
            return Result<Guid>.Invalid("A downgrade needs a justification — it is what the reviewer decides on.");

        var controlId = request.ControlId.Trim();
        if (controlId.Length == 0) return Result<Guid>.Invalid("No control id.");

        var conflicts = await ConflictsAsync(projectId, [(controlId, request.Kind)], ct);
        if (conflicts.Count == 0)
        {
            // Not a downgrade, so it does not need a reviewer and asking for one would
            // put a decision in somebody's queue that the authoring endpoint will take
            // straight away.
            return Result<Guid>.Invalid(
                $"{controlId} is not a downgrade here — author it directly on the project.");
        }

        return await approvals.RequestAsync(
            actor, scope, ApprovalKind.ControlDispositionDowngrade,
            nameof(Project), SubjectId(projectId, controlId),
            justification: $"{conflicts[0].Describe()}. {request.Justification.Trim()}",
            payload: JsonSerializer.Serialize(request with
            {
                ControlId = controlId,
                Justification = request.Justification.Trim(),
            }),
            ct: ct);
    }

    /// <summary>Outstanding downgrade requests on a project, by control id.</summary>
    public async Task<IReadOnlyDictionary<string, PendingApproval>> PendingAsync(
        Guid projectId, CancellationToken ct = default)
    {
        var rows = await approvals.PendingByKindForProjectAsync(
            ApprovalKind.ControlDispositionDowngrade, projectId, ct);

        var byControl = new Dictionary<string, PendingApproval>(StringComparer.OrdinalIgnoreCase);
        foreach (var row in rows)
        {
            // The control id comes off the payload rather than being parsed back out of
            // the subject id, which is a one-way hash.
            if (Read(row) is { } req) byControl[req.ControlId] = row;
        }
        return byControl;
    }

    /// <summary>
    /// The approval subject id for one project's downgrade of one control.
    ///
    /// Derived rather than random so ApprovalService's own duplicate guard applies: two
    /// live requests to downgrade the same control would let a second reviewer approve
    /// the copy of a decision the first one declined. SHA-256 truncated to the 16 bytes
    /// a Guid holds — a hash-to-128-bits function, not a security primitive.
    /// </summary>
    public static Guid SubjectId(Guid projectId, string controlId)
    {
        var key = $"{projectId:N}|downgrade|{controlId.Trim().ToUpperInvariant()}";
        var hash = System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(key));
        return new Guid(hash.AsSpan(0, 16));
    }

    /// <summary>The request off an approval's payload, or null if there is none.</summary>
    public static DowngradeRequest? Read(PendingApproval approval)
    {
        if (approval.Payload is not { Length: > 0 } payload) return null;
        try { return JsonSerializer.Deserialize<DowngradeRequest>(payload); }
        catch (JsonException) { return null; }
    }
}
