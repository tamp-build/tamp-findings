using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Api.Contracts;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

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
           .WithSummary("Upsert Vulnerability rows on SbomComponents in a snapshot. Body: { snapshotId, vulnerabilities: [{ packageName, packageVersion, advisoryId, severity, title, description, referenceUrl }] }. Matching is (Name, Version) exact within the snapshot.");
        return app;
    }

    private static async Task<IResult> UpsertAsync(
        OsvVulnerabilityUpsertRequest req,
        FindingsDbContext db,
        CancellationToken ct)
    {
        if (req.SnapshotId == Guid.Empty) return Results.BadRequest("snapshotId required");
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
        await db.SaveChangesAsync(ct);
        return Results.Ok(new OsvVulnerabilityUpsertResponse(
            SnapshotId: req.SnapshotId,
            Matched: matched,
            Unmatched: unmatched,
            Inserted: inserted,
            Updated: updated));
    }
}
