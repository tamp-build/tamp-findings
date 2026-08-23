using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Application.Auditing;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Projects;
using Tamp.Findings.Application.Risk;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Application.Vex;

/// <summary>
/// Reading and writing VEX statements (TFND-99).
///
/// A VEX statement is the official answer to "why didn't you patch this CVE?".
/// Federal assessors treat it as the answer of record, which sets the bar for
/// this surface: a statement that does not actually relieve the CVE must never
/// look like one that does.
/// </summary>
public sealed class VexQuery
{
    private readonly FindingsDbContext _db;
    private readonly CapabilityEvaluator _capabilities;
    private readonly AuditLog _audit;

    public VexQuery(FindingsDbContext db, CapabilityEvaluator capabilities, AuditLog audit)
    {
        _db = db;
        _capabilities = capabilities;
        _audit = audit;
    }

    public async Task<IReadOnlyList<VexRow>> ListAsync(
        Guid projectId, bool includeRetired = false, CancellationToken ct = default)
    {
        var statements = await _db.VexStatements.AsNoTracking()
            .Where(v => v.ProjectId == projectId && (includeRetired || v.RetiredAt == null))
            .ToArrayAsync(ct);

        var authorIds = statements.Select(v => v.AuthorUserId).Distinct().ToArray();
        var authors = await _db.Users.AsNoTracking()
            .Where(u => authorIds.Contains(u.Id))
            .Select(u => new { u.Id, u.DisplayName })
            .ToArrayAsync(ct);
        var names = authors.ToDictionary(a => a.Id, a => a.DisplayName);

        return statements
            .Select(v => new VexRow(
                v.Id,
                v.AdvisoryId,
                v.Purl,
                v.ComponentVersion,
                v.Status,
                v.Justification,
                v.ImpactStatement,
                v.ResponseReferenceUrl,
                names.TryGetValue(v.AuthorUserId, out var name) ? name : "(unknown)",
                v.CreatedAt,
                v.RetiredAt,
                VexResolver.IsSuppressingStatus(v.Status, v.Justification)))
            // Statements that do NOT relieve the CVE sort first: they are the
            // ones still asking a question. A list ordered by date would bury
            // the unfinished ones under the settled ones.
            .OrderBy(r => r.Suppresses)
            .ThenBy(r => r.AdvisoryId, StringComparer.Ordinal)
            .ThenBy(r => r.Purl, StringComparer.Ordinal)
            .ToArray();
    }

    public async Task<VexRow?> GetAsync(Guid projectId, Guid id, CancellationToken ct = default)
    {
        var all = await ListAsync(projectId, includeRetired: true, ct);
        return all.SingleOrDefault(r => r.Id == id);
    }

    public async Task<Result<Guid>> SaveAsync(
        Principal actor, ScopeTarget scope, Guid projectId, Guid? id, VexDraft draft,
        CancellationToken ct = default)
    {
        // Authoring and publishing are separate capabilities: Lead Dev drafts,
        // InfoSec publishes. A statement that actually relieves a CVE is a
        // published one, so writing a suppressing status needs PublishVex.
        var suppressing = VexResolver.IsSuppressingStatus(draft.Status, draft.Justification);
        var capability = suppressing ? Capability.PublishVex : Capability.AuthorVex;

        var decision = _capabilities.Evaluate(actor, capability);
        if (!decision.Allowed) return Result<Guid>.Denied(decision.Reason!);

        if (Validate(draft) is { } invalid) return Result<Guid>.Invalid(invalid);

        VexStatement statement;
        if (id is { } existing)
        {
            var found = await _db.VexStatements.SingleOrDefaultAsync(
                v => v.Id == existing && v.ProjectId == projectId, ct);
            if (found is null) return Result<Guid>.Invalid("That statement no longer exists.");
            statement = found;
        }
        else
        {
            // Uniqueness is (project, purl, version, advisory). Silently
            // creating a second statement for the same CVE would leave two
            // answers of record and no way to tell which one scoring used.
            var clash = await _db.VexStatements.AnyAsync(
                v => v.ProjectId == projectId
                     && v.RetiredAt == null
                     && v.AdvisoryId == draft.AdvisoryId
                     && v.Purl == draft.Purl
                     && v.ComponentVersion == draft.ComponentVersion, ct);
            if (clash)
                return Result<Guid>.Invalid(
                    $"An active statement already covers {draft.AdvisoryId} for this component. Edit it rather than writing a second answer.");

            statement = new VexStatement
            {
                ProjectId = projectId,
                Purl = draft.Purl.Trim(),
                AdvisoryId = draft.AdvisoryId.Trim(),
                AuthorUserId = actor.UserId,
            };
            _db.VexStatements.Add(statement);
        }

        statement.Purl = draft.Purl.Trim();
        statement.ComponentVersion = Blank(draft.ComponentVersion);
        statement.AdvisoryId = draft.AdvisoryId.Trim();
        statement.Status = draft.Status;
        statement.Justification = draft.Justification;
        statement.ImpactStatement = Blank(draft.ImpactStatement);
        statement.ResponseReferenceUrl = Blank(draft.ResponseReferenceUrl);
        statement.UpdatedAt = DateTimeOffset.UtcNow;

        // Only a suppressing statement is audited as a risk decision, because
        // only a suppressing statement changes the risk picture. A draft under
        // investigation is work in progress.
        _audit.Record(actor,
            suppressing ? AuditActions.VexPublished : "vex.drafted",
            suppressing ? AuditClass.Risk : AuditClass.Other,
            scope,
            subjectId: statement.Id, subjectKind: nameof(VexStatement),
            detail: $"{statement.AdvisoryId} on {statement.Purl}: {statement.Status}"
                  + (statement.Justification is { } j and not VexJustification.None ? $" ({j})" : ""));

        await _db.SaveChangesAsync(ct);
        return Result<Guid>.Ok(statement.Id);
    }

    /// <summary>
    /// Soft-retire. Statements are never deleted: "why did this CVE stop
    /// counting in May?" is a question someone asks years later, and a deleted
    /// row cannot answer it.
    /// </summary>
    public async Task<Result<bool>> RetireAsync(
        Principal actor, ScopeTarget scope, Guid projectId, Guid id, CancellationToken ct = default)
    {
        var decision = _capabilities.Evaluate(actor, Capability.PublishVex);
        if (!decision.Allowed) return Result<bool>.Denied(decision.Reason!);

        var statement = await _db.VexStatements.SingleOrDefaultAsync(
            v => v.Id == id && v.ProjectId == projectId, ct);
        if (statement is null) return Result<bool>.Ok(false);
        if (statement.RetiredAt is not null) return Result<bool>.Ok(false);

        statement.RetiredAt = DateTimeOffset.UtcNow;
        statement.UpdatedAt = statement.RetiredAt.Value;

        // Retiring a suppressing statement puts the CVE back in the count. That
        // is a risk-posture change and is audited as one.
        _audit.Record(actor, "vex.retired", AuditClass.Risk, scope,
            subjectId: statement.Id, subjectKind: nameof(VexStatement),
            detail: $"{statement.AdvisoryId} on {statement.Purl}");

        await _db.SaveChangesAsync(ct);
        return Result<bool>.Ok(true);
    }

    private static string? Validate(VexDraft draft)
    {
        if (draft.AdvisoryId.Trim().Length == 0) return "A statement needs an advisory id.";
        if (draft.Purl.Trim().Length == 0) return "A statement needs a package URL.";
        if (!draft.Purl.TrimStart().StartsWith("pkg:", StringComparison.Ordinal))
            return "The package URL should be a purl, e.g. pkg:nuget/Log4Net.";

        // The rule federal assessors care about most: not_affected always
        // carries a why. Enforced here as well as in VexResolver so the author
        // is told at the point of writing rather than discovering later that
        // their statement counted for nothing.
        if (draft.Status == VexStatementStatus.NotAffected
            && draft.Justification is null or VexJustification.None)
        {
            return "A not_affected statement needs a justification — without one it does not relieve the CVE.";
        }

        if (draft.ResponseReferenceUrl is { Length: > 0 } url
            && !Uri.TryCreate(url.Trim(), UriKind.Absolute, out _))
            return "The reference needs to be a full URL.";

        return null;
    }

    private static string? Blank(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}

public sealed record VexRow(
    Guid Id,
    string AdvisoryId,
    string Purl,
    string? ComponentVersion,
    VexStatementStatus Status,
    VexJustification? Justification,
    string? ImpactStatement,
    string? ResponseReferenceUrl,
    string Author,
    DateTimeOffset CreatedAt,
    DateTimeOffset? RetiredAt,
    /// <summary>
    /// Whether this statement actually takes the CVE out of the gating picture.
    /// A NotAffected with no justification does not, and the table says so.
    /// </summary>
    bool Suppresses);

public sealed record VexDraft(
    string AdvisoryId,
    string Purl,
    string? ComponentVersion,
    VexStatementStatus Status,
    VexJustification? Justification,
    string? ImpactStatement,
    string? ResponseReferenceUrl);
