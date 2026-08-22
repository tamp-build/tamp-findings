using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Api.Endpoints;

// Browse surface for dynamic-scan findings (TFND-38).
//
// Why this isn't just /findings/tree: that endpoint is a module → file tree
// backed by a source viewer, and it explicitly drops findings without a usable
// path into NoPathCount, where they never render. A DAST finding has no source
// file — it has the request the scanner made — so it would be silently
// invisible there. Same two-pane grammar, different spine: host → route
// instead of module → file.
//
// Findings are returned inline with their route rather than behind a second
// detail call. DAST volume is tens-to-hundreds per build, not the thousands a
// SAST tree carries, so one round-trip is cheaper than the extra endpoint. If
// a deployment ever produces enough DAST findings for that to hurt, splitting
// this the way /findings/tree + /findings/file are split is the fix.
public static class DastEndpoints
{
    // Scanners whose findings are runtime observations. Mirrors
    // RiskInputsBuilder.DastSet — see the note there about keeping them aligned.
    private static readonly ScannerKind[] DastScanners = [ScannerKind.Zap, ScannerKind.Nuclei];

    public static IEndpointRouteBuilder MapDast(this IEndpointRouteBuilder app)
    {
        app.MapGet("/findings/dast-tree", GetTreeAsync)
           .WithName("GetDastTree")
           .WithSummary("Host → route tree of open dynamic-scan (ZAP / Nuclei) findings, with the findings inline. Scope filters mirror /aggregates.");
        return app;
    }

    private static async Task<IResult> GetTreeAsync(
        FindingsDbContext db,
        CancellationToken ct,
        Guid? clientId = null,
        Guid? projectId = null,
        Guid? componentId = null,
        bool latest = true)
    {
        var q = db.Findings.AsNoTracking()
            .Where(f => f.Status == FindingStatus.Open && DastScanners.Contains(f.Scanner));

        if (componentId is { } cmp) q = q.Where(f => f.ComponentVersion!.ComponentId == cmp);
        if (projectId is { } prj) q = q.Where(f => f.ComponentVersion!.Component!.ProjectId == prj);
        if (clientId is { } cli) q = q.Where(f => f.ComponentVersion!.Component!.Project!.ClientId == cli);

        if (latest)
        {
            // Same canonical-latest semantic as /findings/tree: the browse view
            // shows the current state, not an accumulation across builds.
            var latestCvIds = await db.ComponentVersions.AsNoTracking()
                .Where(v => v.PullRequestRef == null
                         && (v.BranchName == null || v.BranchName == "main" || v.BranchName == "master"))
                .GroupBy(v => new { v.ComponentId, FlavorKey = v.FlavorId ?? Guid.Empty })
                .Select(g => g.OrderByDescending(v => v.CreatedAt).First().Id)
                .ToListAsync(ct);
            q = q.Where(f => latestCvIds.Contains(f.ComponentVersionId));
        }

        var rows = await q
            .Select(f => new
            {
                f.Id, f.Scanner, f.RuleId, f.Severity, f.Title, f.Description,
                f.FilePath, f.Snippet,
            })
            .ToListAsync(ct);

        if (rows.Count == 0)
        {
            return Results.Ok(new DastTreeResponse(0, ZeroCounts(), []));
        }

        // Group host → route. FilePath carries the scanned URL for a dynamic
        // scanner; DastRoute is shared with FindingHasher so the tree shows
        // exactly the routes dedup considers distinct.
        var hosts = rows
            .Select(r =>
            {
                var (path, paramNames) = DastRoute.Normalize(r.FilePath);
                return new
                {
                    Host = DastRoute.HostOf(r.FilePath),
                    Route = DastRoute.Display(path, paramNames),
                    Row = r,
                };
            })
            .GroupBy(x => x.Host, StringComparer.OrdinalIgnoreCase)
            .Select(hostGroup => new DastHostDto(
                Host: hostGroup.Key,
                Counts: Counts(hostGroup.Select(x => x.Row.Severity)),
                MaxSeverity: hostGroup.Max(x => x.Row.Severity),
                Routes: hostGroup
                    .GroupBy(x => x.Route, StringComparer.Ordinal)
                    .Select(routeGroup => new DastRouteDto(
                        Route: routeGroup.Key,
                        Counts: Counts(routeGroup.Select(x => x.Row.Severity)),
                        MaxSeverity: routeGroup.Max(x => x.Row.Severity),
                        Findings: routeGroup
                            .Select(x => new DastFindingDto(
                                Id: x.Row.Id,
                                Scanner: x.Row.Scanner,
                                RuleId: x.Row.RuleId,
                                Severity: x.Row.Severity,
                                Title: x.Row.Title,
                                Description: x.Row.Description,
                                // The full URL including the payload the
                                // scanner sent — the route strips it, but an
                                // analyst reproducing the finding needs it.
                                Url: x.Row.FilePath,
                                Evidence: x.Row.Snippet))
                            .OrderByDescending(f => f.Severity)
                            .ThenBy(f => f.RuleId, StringComparer.Ordinal)
                            .ToList()))
                    .OrderByDescending(r => r.MaxSeverity)
                    .ThenBy(r => r.Route, StringComparer.Ordinal)
                    .ToList()))
            .OrderByDescending(h => h.MaxSeverity)
            .ThenBy(h => h.Host, StringComparer.OrdinalIgnoreCase)
            .ToList();

        return Results.Ok(new DastTreeResponse(
            TotalCount: rows.Count,
            Counts: Counts(rows.Select(r => r.Severity)),
            Hosts: hosts));
    }

    private static DastSeverityCounts Counts(IEnumerable<Severity> severities)
    {
        int info = 0, low = 0, med = 0, high = 0, crit = 0;
        foreach (var s in severities)
        {
            switch (s)
            {
                case Severity.Info: info++; break;
                case Severity.Low: low++; break;
                case Severity.Medium: med++; break;
                case Severity.High: high++; break;
                case Severity.Critical: crit++; break;
            }
        }
        return new DastSeverityCounts(info, low, med, high, crit);
    }

    private static DastSeverityCounts ZeroCounts() => new(0, 0, 0, 0, 0);
}

public sealed record DastSeverityCounts(int Info, int Low, int Medium, int High, int Critical);

public sealed record DastFindingDto(
    Guid Id,
    ScannerKind Scanner,
    string RuleId,
    Severity Severity,
    string Title,
    string? Description,
    string? Url,
    string? Evidence);

public sealed record DastRouteDto(
    string Route,
    DastSeverityCounts Counts,
    Severity MaxSeverity,
    IReadOnlyList<DastFindingDto> Findings);

public sealed record DastHostDto(
    string Host,
    DastSeverityCounts Counts,
    Severity MaxSeverity,
    IReadOnlyList<DastRouteDto> Routes);

public sealed record DastTreeResponse(
    int TotalCount,
    DastSeverityCounts Counts,
    IReadOnlyList<DastHostDto> Hosts);
