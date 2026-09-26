using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Api.Authentication;
using Tamp.Findings.Api.Contracts;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

using Tamp.Findings.Application.Auditing;

namespace Tamp.Findings.Api.Endpoints;

// TFND-16: fold OsvScanner findings into SbomComponent.Vulnerabilities so
// the SBOM ring's "vulnerable" bucket reflects every known CVE, not just
// the Grype-enriched ones. Match by (Name, Version) within the given
// snapshot — anything we can't match is reported back as an unmatched
// count so the caller can see triage debt.
public static class SbomVulnerabilitiesEndpoints
{
    public static IEndpointRouteBuilder MapSbomVulnerabilities(this IEndpointRouteBuilder app)
    {
        app.MapPost("/sbom-vulnerabilities/upsert", UpsertAsync)
           .WithName("UpsertSbomVulnerabilities")
           .WithSummary("Upsert Vulnerability rows on SbomComponents in a snapshot. Body: { snapshotId, vulnerabilities: [{ packageName, packageVersion, advisoryId, severity, title, description, referenceUrl }] }. Matching is (Name, Version) exact within the snapshot. Requires Authorization: Bearer cli_… or prj_…")
           // AllowAnonymous opts out of the cookie FallbackPolicy; the
           // bearer filter is what actually guards the route. Without the
           // filter this was an unauthenticated write into any snapshot by
           // guid, bypassing IngestScopeGuard's cli_/prj_ scoping entirely
           // — injected rows feed the risk score, KEV gate, and SSDF
           // attestation. The build already sends the token (IngestClient
           // line 84), so this is a no-op for the pipeline.
           .AllowAnonymous()
           .AddEndpointFilter<IngestAuthFilter>();
        return app;
    }

    private static async Task<IResult> UpsertAsync(
        OsvVulnerabilityUpsertRequest req,
        HttpContext ctx,
        AuditLog audit,
        FindingsDbContext db,
        CancellationToken ct)
    {
        if (req.SnapshotId == Guid.Empty) return Results.BadRequest("snapshotId required");

        // TFND-163: scope the snapshot to the token. Unlike the /ingest/* routes,
        // this endpoint is addressed by a snapshot guid and never ran through
        // IngestScopeGuard, so a valid tenant-A token could inject CVE rows into
        // tenant-B's snapshot — rows that feed the risk score, KEV gate and SSDF
        // attestation. Resolve the snapshot's owning project/client and refuse
        // out-of-scope tokens; out of scope reads as not-found, never a
        // confirmation that another tenant's snapshot exists.
        var owner = await db.SbomSnapshots.AsNoTracking()
            .Where(s => s.Id == req.SnapshotId)
            .Select(s => new { s.ComponentVersion!.Component!.ProjectId, ClientId = s.ComponentVersion.Component.Project!.ClientId })
            .FirstOrDefaultAsync(ct);
        if (owner is null) return Results.NotFound("snapshot not found");

        var token = IngestAuthFilter.CurrentToken(ctx);
        if (token is null) return Results.Unauthorized();
        var inScope = token.Scope == IngestTokenScope.Project
            ? token.ProjectId == owner.ProjectId
            : token.ClientId == owner.ClientId;
        if (!inScope) return Results.NotFound("snapshot not found");

        var components = await db.SbomComponents.AsNoTracking()
            .Where(c => c.SbomSnapshotId == req.SnapshotId)
            .Select(c => new { c.Id, c.Name, c.Version })
            .ToListAsync(ct);
        // Component index: (Name, Version) → Id. Name match is case-insensitive
        // to forgive ecosystem casing inconsistencies (npm = lower, NuGet = PascalCase).
        var index = components
            .GroupBy(c => $"{c.Name.ToLowerInvariant()}|{c.Version}", StringComparer.Ordinal)
            .ToDictionary(g => g.Key, g => g.First().Id);

        int matched = 0, unmatched = 0, inserted = 0, updated = 0;
        foreach (var v in req.Vulnerabilities ?? [])
        {
            var key = $"{v.PackageName.ToLowerInvariant()}|{v.PackageVersion}";
            if (!index.TryGetValue(key, out var componentId))
            {
                unmatched++;
                continue;
            }
            matched++;
            var existing = await db.Vulnerabilities
                .FirstOrDefaultAsync(x => x.SbomComponentId == componentId && x.AdvisoryId == v.AdvisoryId, ct);
            if (existing is null)
            {
                db.Vulnerabilities.Add(new Vulnerability
                {
                    SbomComponentId = componentId,
                    AdvisoryId = v.AdvisoryId,
                    Severity = v.Severity,
                    Title = v.Title,
                    Description = v.Description,
                    ReferenceUrl = v.ReferenceUrl,
                    Source = ScannerKind.OsvScanner,
                });
                inserted++;
            }
            else
            {
                // Keep the higher severity if Grype and OSV disagree.
                if (v.Severity > existing.Severity) existing.Severity = v.Severity;
                existing.Title ??= v.Title;
                existing.Description ??= v.Description;
                existing.ReferenceUrl ??= v.ReferenceUrl;
                updated++;
            }
        }
        await IngestAudit.RecordForSnapshotAsync(audit, db, IngestAuthFilter.CurrentToken(ctx), req.SnapshotId,
            $"sbom-vulnerabilities: {matched} matched, {inserted} inserted, {updated} updated, {unmatched} unmatched — snapshot {req.SnapshotId}", ct);
        await db.SaveChangesAsync(ct);
        return Results.Ok(new OsvVulnerabilityUpsertResponse(
            SnapshotId: req.SnapshotId,
            Matched: matched,
            Unmatched: unmatched,
            Inserted: inserted,
            Updated: updated));
    }
}
