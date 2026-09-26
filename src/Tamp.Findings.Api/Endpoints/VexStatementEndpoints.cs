using System.Text.Json;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Vex;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Api.Endpoints;

public sealed record VexStatementDto(
    Guid Id,
    Guid ProjectId,
    string Purl,
    string? ComponentVersion,
    string AdvisoryId,
    VexStatementStatus Status,
    VexJustification? Justification,
    string? ImpactStatement,
    string? ResponseReferenceUrl,
    Guid AuthorUserId,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt,
    DateTimeOffset? RetiredAt);

public sealed record CreateVexStatementRequest(
    string Purl,
    string? ComponentVersion,
    string AdvisoryId,
    VexStatementStatus Status,
    VexJustification? Justification,
    string? ImpactStatement,
    string? ResponseReferenceUrl);

public sealed record UpdateVexStatementRequest(
    VexStatementStatus? Status,
    VexJustification? Justification,
    string? ImpactStatement,
    string? ResponseReferenceUrl);

public sealed record CycloneDxVexIngestResponse(int Created, int Updated, int Skipped, int Failed);

// TFND-156: writes route through VexQuery — the same capability-gated, audited
// path the Blazor UI uses — instead of an Admin-only, unaudited path. Authoring
// needs AuthorVex; a statement that actually suppresses a CVE needs PublishVex,
// and VexQuery decides which per statement. The bulk import applies the same
// check to every statement it writes.
public static class VexStatementEndpoints
{
    public static IEndpointRouteBuilder MapVexStatements(this IEndpointRouteBuilder app)
    {
        var g = app.MapGroup("").WithTags("VEX");

        g.MapGet("/projects/{projectId:guid}/vex-statements", ListAsync)
         .WithSummary("List VEX statements for a project (current + optionally retired).");
        g.MapPost("/projects/{projectId:guid}/vex-statements", CreateAsync)
         .WithSummary("Author a new VEX statement. Needs AuthorVex; a suppressing status needs PublishVex.");
        g.MapPost("/projects/{projectId:guid}/vex-statements/ingest-cdx", IngestCycloneDxAsync)
         .WithSummary("Bulk-author VEX statements from a CycloneDX-VEX 1.5+ JSON document. Each statement is capability-checked and audited individually.");

        g.MapPatch("/vex-statements/{id:guid}", UpdateAsync)
         .WithSummary("Edit a VEX statement in place. Bumps UpdatedAt; preserves CreatedAt.");
        g.MapDelete("/vex-statements/{id:guid}", RetireAsync)
         .WithSummary("Soft-retire a VEX statement (sets RetiredAt). Row stays for audit; stops applying at score time.");

        return app;
    }

    private static async Task<Ok<IReadOnlyList<VexStatementDto>>> ListAsync(
        Guid projectId, FindingsDbContext db, CancellationToken ct, bool includeRetired = false)
    {
        var q = db.VexStatements.AsNoTracking().Where(v => v.ProjectId == projectId);
        if (!includeRetired) q = q.Where(v => v.RetiredAt == null);
        var rows = await q.OrderByDescending(v => v.UpdatedAt).Select(v => Project(v)).ToListAsync(ct);
        return TypedResults.Ok((IReadOnlyList<VexStatementDto>)rows);
    }

    private static async Task<IResult> CreateAsync(
        Guid projectId, CreateVexStatementRequest req, HttpContext ctx, FindingsDbContext db,
        PrincipalResolver principals, VexQuery vex, CancellationToken ct)
    {
        var (actor, scope, deny) = await EndpointActor.ForProjectAsync(ctx, db, principals, projectId, ct);
        if (deny is not null) return deny;

        var draft = new VexDraft(
            req.AdvisoryId ?? "", req.Purl ?? "", req.ComponentVersion,
            req.Status, req.Justification, req.ImpactStatement, req.ResponseReferenceUrl);

        var result = await vex.SaveAsync(actor!, scope, projectId, id: null, draft, ct);
        if (!result.Success) return Fail(result.WasDenied, result.Error);

        var row = await db.VexStatements.AsNoTracking().FirstAsync(v => v.Id == result.Value, ct);
        return Results.Created($"/vex-statements/{row.Id}", Project(row));
    }

    private static async Task<IResult> UpdateAsync(
        Guid id, UpdateVexStatementRequest req, HttpContext ctx, FindingsDbContext db,
        PrincipalResolver principals, VexQuery vex, CancellationToken ct)
    {
        var row = await db.VexStatements.AsNoTracking().FirstOrDefaultAsync(v => v.Id == id, ct);
        if (row is null) return Results.NotFound();
        if (row.RetiredAt is not null) return Results.Conflict("statement retired; create a new one instead");

        var (actor, scope, deny) = await EndpointActor.ForProjectAsync(ctx, db, principals, row.ProjectId, ct);
        if (deny is not null) return deny;

        // Advisory + purl are the statement's identity and are not edited here;
        // a status change may cross from AuthorVex into PublishVex, which
        // VexQuery.SaveAsync enforces.
        var draft = new VexDraft(
            row.AdvisoryId,
            row.Purl,
            row.ComponentVersion,
            req.Status ?? row.Status,
            req.Justification ?? row.Justification,
            req.ImpactStatement ?? row.ImpactStatement,
            req.ResponseReferenceUrl ?? row.ResponseReferenceUrl);

        var result = await vex.SaveAsync(actor!, scope, row.ProjectId, row.Id, draft, ct);
        if (!result.Success) return Fail(result.WasDenied, result.Error);

        var updated = await db.VexStatements.AsNoTracking().FirstAsync(v => v.Id == id, ct);
        return Results.Ok(Project(updated));
    }

    private static async Task<IResult> RetireAsync(
        Guid id, HttpContext ctx, FindingsDbContext db,
        PrincipalResolver principals, VexQuery vex, CancellationToken ct)
    {
        var projectId = await db.VexStatements.AsNoTracking()
            .Where(v => v.Id == id).Select(v => (Guid?)v.ProjectId).FirstOrDefaultAsync(ct);
        if (projectId is null) return Results.NotFound();

        var (actor, scope, deny) = await EndpointActor.ForProjectAsync(ctx, db, principals, projectId.Value, ct);
        if (deny is not null) return deny;

        var result = await vex.RetireAsync(actor!, scope, projectId.Value, id, ct);
        if (!result.Success) return Fail(result.WasDenied, result.Error);
        return Results.NoContent();
    }

    // CycloneDX-VEX 1.5+ JSON body: top-level `vulnerabilities` array, each with
    // `id` (CVE), `analysis.state`, and an `affects` array of `{ ref }`. Every
    // statement written goes through VexQuery.SaveAsync, so each is
    // capability-checked (Author/Publish) and audited — a bulk import is not a
    // way around the per-statement rules.
    private static async Task<IResult> IngestCycloneDxAsync(
        Guid projectId, HttpRequest httpReq, HttpContext ctx, FindingsDbContext db,
        PrincipalResolver principals, VexQuery vex, CancellationToken ct)
    {
        var (actor, scope, deny) = await EndpointActor.ForProjectAsync(ctx, db, principals, projectId, ct);
        if (deny is not null) return deny;

        JsonDocument doc;
        try { doc = await JsonDocument.ParseAsync(httpReq.Body, cancellationToken: ct); }
        catch (JsonException ex) { return Results.BadRequest("invalid JSON: " + ex.Message); }
        using (doc)
        {
            if (!doc.RootElement.TryGetProperty("vulnerabilities", out var vulnsEl) || vulnsEl.ValueKind != JsonValueKind.Array)
                return Results.BadRequest("expected top-level `vulnerabilities` array");

            int created = 0, updated = 0, skipped = 0, failed = 0;

            // Ids of the active statements, so an upsert reuses the row rather
            // than duplicating it. Grows as new ones are created in this doc.
            var idByKey = await db.VexStatements.AsNoTracking()
                .Where(v => v.ProjectId == projectId && v.RetiredAt == null)
                .Select(v => new { v.Id, v.AdvisoryId, v.Purl, v.ComponentVersion })
                .ToDictionaryAsync(v => (v.AdvisoryId, v.Purl, v.ComponentVersion), v => v.Id, ct);

            foreach (var v in vulnsEl.EnumerateArray())
            {
                var advisoryId = v.TryGetProperty("id", out var idEl) && idEl.ValueKind == JsonValueKind.String
                    ? idEl.GetString() : null;
                if (string.IsNullOrWhiteSpace(advisoryId)) { failed++; continue; }

                var state = v.TryGetProperty("analysis", out var an)
                    && an.TryGetProperty("state", out var stEl)
                    && stEl.ValueKind == JsonValueKind.String
                        ? stEl.GetString() : null;
                if (!TryMapCdxState(state, out var status)) { skipped++; continue; }

                var justification = an.ValueKind == JsonValueKind.Object
                    && an.TryGetProperty("justification", out var jEl)
                    && jEl.ValueKind == JsonValueKind.String
                        ? MapCdxJustification(jEl.GetString()) : (VexJustification?)null;

                var impact = an.ValueKind == JsonValueKind.Object
                    && an.TryGetProperty("detail", out var dEl)
                    && dEl.ValueKind == JsonValueKind.String
                        ? dEl.GetString() : null;

                if (!v.TryGetProperty("affects", out var affectsEl) || affectsEl.ValueKind != JsonValueKind.Array)
                {
                    skipped++;
                    continue;
                }

                foreach (var aff in affectsEl.EnumerateArray())
                {
                    var purl = ExtractPurl(aff);
                    if (string.IsNullOrWhiteSpace(purl)) { skipped++; continue; }
                    var (bare, ver) = SplitPurlVersion(purl);
                    var key = (advisoryId!, bare, ver);

                    Guid? existingId = idByKey.TryGetValue(key, out var eid) ? eid : null;
                    var draft = new VexDraft(advisoryId!, bare, ver, status, justification, impact, null);

                    var r = await vex.SaveAsync(actor!, scope, projectId, existingId, draft, ct);
                    if (!r.Success)
                    {
                        // A capability denial aborts the whole import — the actor
                        // cannot author/publish here, so counting it as a per-row
                        // failure would hide that.
                        if (r.WasDenied) return Results.Problem(r.Error, statusCode: StatusCodes.Status403Forbidden);
                        failed++;
                        continue;
                    }

                    if (existingId is null) { created++; idByKey[key] = r.Value; }
                    else updated++;
                }
            }

            return Results.Ok(new CycloneDxVexIngestResponse(created, updated, skipped, failed));
        }
    }

    private static IResult Fail(bool denied, string? error) =>
        denied ? Results.Problem(error, statusCode: StatusCodes.Status403Forbidden)
               : Results.BadRequest(error);

    private static string? ExtractPurl(JsonElement aff)
    {
        if (aff.TryGetProperty("ref", out var refEl) && refEl.ValueKind == JsonValueKind.String)
        {
            var s = refEl.GetString();
            if (!string.IsNullOrWhiteSpace(s) && s.StartsWith("pkg:", StringComparison.Ordinal)) return s;
        }
        if (aff.TryGetProperty("purl", out var pEl) && pEl.ValueKind == JsonValueKind.String) return pEl.GetString();
        return null;
    }

    // pkg:nuget/Log4Net@2.0.5 → ("pkg:nuget/Log4Net", "2.0.5")
    private static (string Bare, string? Version) SplitPurlVersion(string purl)
    {
        var at = purl.LastIndexOf('@');
        if (at < 4) return (purl, null);
        return (purl[..at], purl[(at + 1)..]);
    }

    private static bool TryMapCdxState(string? state, out VexStatementStatus status)
    {
        status = VexStatementStatus.UnderInvestigation;
        switch (state?.ToLowerInvariant())
        {
            case "in_triage": case "under_investigation": status = VexStatementStatus.UnderInvestigation; return true;
            case "exploitable": status = VexStatementStatus.Affected; return true;
            case "false_positive": case "not_affected": status = VexStatementStatus.NotAffected; return true;
            case "resolved": case "resolved_with_pedigree": case "fixed": status = VexStatementStatus.Fixed; return true;
            default: return false;
        }
    }

    private static VexJustification? MapCdxJustification(string? j) => j?.ToLowerInvariant() switch
    {
        "code_not_present"                            => VexJustification.VulnerableCodeNotPresent,
        "component_not_present"                       => VexJustification.ComponentNotPresent,
        "code_not_reachable"                          => VexJustification.VulnerableCodeNotInExecutePath,
        "requires_configuration"                      => VexJustification.VulnerableCodeNotInExecutePath,
        "requires_dependency"                         => VexJustification.VulnerableCodeNotInExecutePath,
        "requires_environment"                        => VexJustification.VulnerableCodeNotInExecutePath,
        "protected_by_compiler"                       => VexJustification.InlineMitigationsAlreadyExist,
        "protected_at_runtime"                        => VexJustification.InlineMitigationsAlreadyExist,
        "protected_at_perimeter"                      => VexJustification.InlineMitigationsAlreadyExist,
        "protected_by_mitigating_control"             => VexJustification.InlineMitigationsAlreadyExist,
        _                                             => null,
    };

    private static VexStatementDto Project(VexStatement v) => new(
        v.Id, v.ProjectId, v.Purl, v.ComponentVersion, v.AdvisoryId,
        v.Status, v.Justification, v.ImpactStatement, v.ResponseReferenceUrl,
        v.AuthorUserId, v.CreatedAt, v.UpdatedAt, v.RetiredAt);
}
