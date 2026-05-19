using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Api.Contracts;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Api.Endpoints;

public static class FindingsQueryEndpoints
{
    public static IEndpointRouteBuilder MapFindingsQuery(this IEndpointRouteBuilder app)
    {
        app.MapGet("/findings/by-component-version/{id:guid}", ByComponentVersionAsync)
           .WithName("FindingsByComponentVersion")
           .WithSummary("List all findings for a component version with severity counts");
        return app;
    }

    private static async Task<IResult> ByComponentVersionAsync(Guid id, FindingsDbContext db, CancellationToken ct)
    {
        var version = await db.ComponentVersions.FirstOrDefaultAsync(v => v.Id == id, ct);
        if (version is null) return Results.NotFound();

        var rows = await db.Findings
            .Where(f => f.ComponentVersionId == id)
            .OrderByDescending(f => f.Severity)
            .ThenBy(f => f.RuleId)
            .Select(f => new FindingSummary(
                f.Id,
                f.Scanner,
                f.RuleId,
                f.Severity,
                f.Title,
                f.FilePath,
                f.Line,
                f.Status,
                f.FirstSeen,
                f.LastSeen))
            .ToListAsync(ct);

        var counts = new SeverityCounts(
            rows.Count(r => r.Severity == Severity.Info),
            rows.Count(r => r.Severity == Severity.Low),
            rows.Count(r => r.Severity == Severity.Medium),
            rows.Count(r => r.Severity == Severity.High),
            rows.Count(r => r.Severity == Severity.Critical));

        return Results.Ok(new ComponentVersionFindings(version.Id, version.VersionString, counts, rows));
    }
}
