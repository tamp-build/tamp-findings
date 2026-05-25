using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Api.Authentication;
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

public static class VexStatementEndpoints
{
    public static IEndpointRouteBuilder MapVexStatements(this IEndpointRouteBuilder app)
    {
        var g = app.MapGroup("").WithTags("VEX");

        g.MapGet("/projects/{projectId:guid}/vex-statements", ListAsync)
         .WithSummary("List VEX statements for a project (current + optionally retired).");
        g.MapPost("/projects/{projectId:guid}/vex-statements", CreateAsync)
         .WithSummary("Author a new VEX statement for a project. Admin only today; TFND-3 role check lands later.");
        g.MapPost("/projects/{projectId:guid}/vex-statements/ingest-cdx", IngestCycloneDxAsync)
         .WithSummary("Bulk-author VEX statements from a CycloneDX-VEX 1.5+ JSON document. Each `vulnerabilities[]` entry produces one statement per affected component.");

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
        Guid projectId, CreateVexStatementRequest req, HttpContext ctx, FindingsDbContext db, CancellationToken ct)
    {
        var (user, deny) = await RequireAdminAsync(ctx, db, ct);
        if (deny is not null) return deny;
        if (string.IsNullOrWhiteSpace(req.Purl)) return Results.BadRequest("purl required");
        if (string.IsNullOrWhiteSpace(req.AdvisoryId)) return Results.BadRequest("advisoryId required");
        if (!await db.Projects.AnyAsync(p => p.Id == projectId, ct)) return Results.NotFound("project not found");

        var row = new VexStatement
        {
            ProjectId = projectId,
            Purl = req.Purl.Trim(),
            ComponentVersion = string.IsNullOrWhiteSpace(req.ComponentVersion) ? null : req.ComponentVersion.Trim(),
            AdvisoryId = req.AdvisoryId.Trim(),
            Status = req.Status,
            Justification = req.Justification,
            ImpactStatement = req.ImpactStatement,
            ResponseReferenceUrl = req.ResponseReferenceUrl,
            AuthorUserId = user!.Id,
        };
        db.VexStatements.Add(row);
        await db.SaveChangesAsync(ct);
        return Results.Created($"/vex-statements/{row.Id}", Project(row));
    }

    private static async Task<IResult> UpdateAsync(
        Guid id, UpdateVexStatementRequest req, HttpContext ctx, FindingsDbContext db, CancellationToken ct)
    {
        var (_, deny) = await RequireAdminAsync(ctx, db, ct);
        if (deny is not null) return deny;
        var row = await db.VexStatements.FirstOrDefaultAsync(v => v.Id == id, ct);
        if (row is null) return Results.NotFound();
        if (row.RetiredAt is not null) return Results.Conflict("statement retired; create a new one instead");

        if (req.Status.HasValue) row.Status = req.Status.Value;
        if (req.Justification.HasValue) row.Justification = req.Justification;
        if (req.ImpactStatement is not null) row.ImpactStatement = string.IsNullOrWhiteSpace(req.ImpactStatement) ? null : req.ImpactStatement;
        if (req.ResponseReferenceUrl is not null) row.ResponseReferenceUrl = string.IsNullOrWhiteSpace(req.ResponseReferenceUrl) ? null : req.ResponseReferenceUrl;
        row.UpdatedAt = DateTimeOffset.UtcNow;
        await db.SaveChangesAsync(ct);
        return Results.Ok(Project(row));
    }

    private static async Task<IResult> RetireAsync(
        Guid id, HttpContext ctx, FindingsDbContext db, CancellationToken ct)
    {
        var (_, deny) = await RequireAdminAsync(ctx, db, ct);
        if (deny is not null) return deny;
        var row = await db.VexStatements.FirstOrDefaultAsync(v => v.Id == id, ct);
        if (row is null) return Results.NotFound();
        if (row.RetiredAt is not null) return Results.NoContent();
        row.RetiredAt = DateTimeOffset.UtcNow;
        await db.SaveChangesAsync(ct);
        return Results.NoContent();
    }

    // CycloneDX-VEX 1.5+ JSON body: top-level `vulnerabilities` array,
    // each entry with `id` (CVE), `analysis.state`, and an `affects`
    // array of `{ ref: <bom-ref> }` pointing at components. Federal
    // VEX tooling (semgrep-vexctl, dependency-track-vex, etc.) all
    // produce this shape.
    //
    // Parsing strategy: a CycloneDX-VEX doc usually accompanies an
    // SBOM and the bom-refs in `affects[].ref` are either component
    // ids local to the SBOM or full purls. We're permissive — accept
    // anything that parses as a purl (or has a `purl` sibling on the
    // ref entry) and persist it as a project-scoped statement.
    private static async Task<IResult> IngestCycloneDxAsync(
        Guid projectId, HttpRequest httpReq, HttpContext ctx, FindingsDbContext db, CancellationToken ct)
    {
        var (user, deny) = await RequireAdminAsync(ctx, db, ct);
        if (deny is not null) return deny;
        if (!await db.Projects.AnyAsync(p => p.Id == projectId, ct)) return Results.NotFound("project not found");

        JsonDocument doc;
        try { doc = await JsonDocument.ParseAsync(httpReq.Body, cancellationToken: ct); }
        catch (JsonException ex) { return Results.BadRequest("invalid JSON: " + ex.Message); }
        using (doc)
        {
            if (!doc.RootElement.TryGetProperty("vulnerabilities", out var vulnsEl) || vulnsEl.ValueKind != JsonValueKind.Array)
                return Results.BadRequest("expected top-level `vulnerabilities` array");

            int created = 0, updated = 0, skipped = 0, failed = 0;
            // Pre-load existing active statements once so the loop can
            // upsert in memory without N round-trips.
            var existing = await db.VexStatements
                .Where(v => v.ProjectId == projectId && v.RetiredAt == null)
                .ToListAsync(ct);
            var byKey = existing.ToDictionary(v => (v.AdvisoryId, v.Purl, v.ComponentVersion), v => v);

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
                    // CycloneDX-VEX allows a vulnerability without
                    // explicit affects when the parent BOM context
                    // disambiguates. We can't act on a project-scoped
                    // statement without a target — skip with a count.
                    skipped++;
                    continue;
                }

                foreach (var aff in affectsEl.EnumerateArray())
                {
                    var purl = ExtractPurl(aff);
                    if (string.IsNullOrWhiteSpace(purl)) { skipped++; continue; }
                    var (bare, ver) = SplitPurlVersion(purl);
                    var key = (advisoryId!, bare, ver);
                    if (byKey.TryGetValue(key, out var row))
                    {
                        row.Status = status;
                        row.Justification = justification;
                        row.ImpactStatement = impact ?? row.ImpactStatement;
                        row.UpdatedAt = DateTimeOffset.UtcNow;
                        updated++;
                    }
                    else
                    {
                        var fresh = new VexStatement
                        {
                            ProjectId = projectId,
                            Purl = bare,
                            ComponentVersion = ver,
                            AdvisoryId = advisoryId!,
                            Status = status,
                            Justification = justification,
                            ImpactStatement = impact,
                            AuthorUserId = user!.Id,
                        };
                        db.VexStatements.Add(fresh);
                        byKey[key] = fresh;
                        created++;
                    }
                }
            }
            await db.SaveChangesAsync(ct);
            return Results.Ok(new CycloneDxVexIngestResponse(created, updated, skipped, failed));
        }
    }

    private static string? ExtractPurl(JsonElement aff)
    {
        // Two common shapes:
        // 1. { "ref": "pkg:nuget/Log4Net@2.0.5" } — full purl in ref
        // 2. { "ref": "<bom-ref>" } + sibling fields (not common in
        //    pure-VEX). Today we only read the ref if it looks like
        //    a purl; bom-ref resolution against an external SBOM is
        //    out of scope until we wire ingest pairing.
        if (aff.TryGetProperty("ref", out var refEl) && refEl.ValueKind == JsonValueKind.String)
        {
            var s = refEl.GetString();
            if (!string.IsNullOrWhiteSpace(s) && s.StartsWith("pkg:", StringComparison.Ordinal)) return s;
        }
        if (aff.TryGetProperty("purl", out var pEl) && pEl.ValueKind == JsonValueKind.String) return pEl.GetString();
        return null;
    }

    // pkg:nuget/Log4Net@2.0.5 → ("pkg:nuget/Log4Net", "2.0.5")
    // pkg:nuget/Log4Net      → ("pkg:nuget/Log4Net", null)
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

    private static async Task<(User? user, IResult? deny)> RequireAdminAsync(HttpContext ctx, FindingsDbContext db, CancellationToken ct)
    {
        if (!Guid.TryParse(ctx.User.FindFirstValue(AuthExtensions.TampUserIdClaim), out var uid))
            return (null, Results.Unauthorized());
        var user = await db.Users.FirstOrDefaultAsync(u => u.Id == uid, ct);
        if (user is null || !user.IsApproved) return (null, Results.Unauthorized());
        if (!user.IsAdmin) return (user, Results.Forbid());
        return (user, null);
    }
}
