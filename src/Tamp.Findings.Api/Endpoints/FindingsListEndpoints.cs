using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Api.Contracts;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Api.Endpoints;

public static class FindingsListEndpoints
{
    public static IEndpointRouteBuilder MapFindingsList(this IEndpointRouteBuilder app)
    {
        app.MapGet("/findings", ListFindingsAsync)
           .WithName("ListFindings")
           .WithSummary("Cross-version findings list with filters and severity roll-up");

        app.MapGet("/clients", ListClientsAsync)
           .WithName("ListClients")
           .WithSummary("Clients with project counts");

        app.MapGet("/projects", ListProjectsAsync)
           .WithName("ListProjects")
           .WithSummary("Projects (optionally filtered by client) with component counts");

        app.MapGet("/components", ListComponentsAsync)
           .WithName("ListComponents")
           .WithSummary("Components (optionally filtered by project) with version counts");

        return app;
    }

    private static async Task<Ok<FindingsListResponse>> ListFindingsAsync(
        FindingsDbContext db,
        CancellationToken ct,
        Guid? clientId = null,
        Guid? projectId = null,
        Guid? componentId = null,
        Guid? componentVersionId = null,
        string? severity = null,
        string? scanner = null,
        string? status = null,
        string? search = null,
        bool latest = true,
        int skip = 0,
        int take = 100)
    {
        take = Math.Clamp(take, 1, 500);
        skip = Math.Max(skip, 0);

        var severities = ParseEnumCsv<Severity>(severity);
        var scanners = ParseEnumCsv<ScannerKind>(scanner);
        var statuses = ParseEnumCsv<FindingStatus>(status);

        var q = db.Findings
            .Include(f => f.ComponentVersion)!.ThenInclude(v => v!.Component)!.ThenInclude(c => c!.Project)!.ThenInclude(p => p!.Client)
            .AsNoTracking();

        if (componentVersionId is { } cv) q = q.Where(f => f.ComponentVersionId == cv);
        if (componentId is { } cmp) q = q.Where(f => f.ComponentVersion!.ComponentId == cmp);
        if (projectId is { } prj) q = q.Where(f => f.ComponentVersion!.Component!.ProjectId == prj);
        if (clientId is { } cli) q = q.Where(f => f.ComponentVersion!.Component!.Project!.ClientId == cli);
        if (severities.Count > 0) q = q.Where(f => severities.Contains(f.Severity));
        if (scanners.Count > 0) q = q.Where(f => scanners.Contains(f.Scanner));

        // Status filter defaults to Open only — the Inbox is for "what
        // currently needs attention". Pass status=Open,Suppressed to peek
        // at the suppressed pile, or include Fixed for historical review.
        if (statuses.Count > 0) q = q.Where(f => statuses.Contains(f.Status));
        else q = q.Where(f => f.Status == FindingStatus.Open);

        if (!string.IsNullOrWhiteSpace(search))
        {
            var s = search.Trim();
            q = q.Where(f => EF.Functions.ILike(f.Title, $"%{s}%") || EF.Functions.ILike(f.RuleId, $"%{s}%"));
        }

        // Default: scope to the latest ComponentVersion per (Component,
        // Flavor). Without this, every historical commit's findings pile
        // up in the Inbox forever — auto-close only acts within a single
        // ComponentVersion, not across them. Pass latest=false to see
        // everything across builds.
        if (latest)
        {
            var latestCvIds = await db.ComponentVersions
                .GroupBy(v => new
                {
                    v.ComponentId,
                    FlavorKey = v.FlavorId ?? Guid.Empty,
                })
                .Select(g => g.OrderByDescending(v => v.CreatedAt).First().Id)
                .ToListAsync(ct);
            q = q.Where(f => latestCvIds.Contains(f.ComponentVersionId));
        }

        var total = await q.CountAsync(ct);

        // Aggregation per F1.2 is sums, so just count by bucket here.
        var counts = await q
            .GroupBy(f => f.Severity)
            .Select(g => new { Severity = g.Key, Count = g.Count() })
            .ToDictionaryAsync(x => x.Severity, x => x.Count, ct);

        var items = await q
            .OrderByDescending(f => f.Severity)
            .ThenByDescending(f => f.LastSeen)
            .ThenBy(f => f.RuleId)
            .Skip(skip)
            .Take(take)
            .Select(f => new FindingListItem(
                f.Id,
                f.Scanner,
                f.RuleId,
                f.Severity,
                f.Title,
                f.FilePath,
                f.Line,
                f.Status,
                f.FirstSeen,
                f.LastSeen,
                f.ComponentVersionId,
                f.ComponentVersion!.VersionString,
                f.ComponentVersion.ComponentId,
                f.ComponentVersion.Component!.Name,
                f.ComponentVersion.Component.ProjectId,
                f.ComponentVersion.Component.Project!.Name,
                f.ComponentVersion.Component.Project.ClientId,
                f.ComponentVersion.Component.Project.Client!.Name))
            .ToListAsync(ct);

        var sc = new SeverityCounts(
            counts.GetValueOrDefault(Severity.Info, 0),
            counts.GetValueOrDefault(Severity.Low, 0),
            counts.GetValueOrDefault(Severity.Medium, 0),
            counts.GetValueOrDefault(Severity.High, 0),
            counts.GetValueOrDefault(Severity.Critical, 0));

        return TypedResults.Ok(new FindingsListResponse(total, skip, take, sc, items));
    }

    private static async Task<Ok<IReadOnlyList<ClientListItem>>> ListClientsAsync(FindingsDbContext db, CancellationToken ct)
    {
        var rows = await db.Clients
            .AsNoTracking()
            .OrderBy(c => c.Name)
            .Select(c => new ClientListItem(c.Id, c.Name, c.Projects.Count))
            .ToListAsync(ct);
        return TypedResults.Ok((IReadOnlyList<ClientListItem>)rows);
    }

    private static async Task<Ok<IReadOnlyList<ProjectListItem>>> ListProjectsAsync(FindingsDbContext db, CancellationToken ct, Guid? clientId = null)
    {
        var q = db.Projects.AsNoTracking();
        if (clientId is { } cli) q = q.Where(p => p.ClientId == cli);
        var rows = await q
            .OrderBy(p => p.Name)
            .Select(p => new ProjectListItem(p.Id, p.Name, p.ClientId, p.Client!.Name, p.Components.Count))
            .ToListAsync(ct);
        return TypedResults.Ok((IReadOnlyList<ProjectListItem>)rows);
    }

    private static async Task<Ok<IReadOnlyList<ComponentListItem>>> ListComponentsAsync(FindingsDbContext db, CancellationToken ct, Guid? projectId = null)
    {
        var q = db.Components.AsNoTracking();
        if (projectId is { } prj) q = q.Where(c => c.ProjectId == prj);
        var rows = await q
            .OrderBy(c => c.Name)
            .Select(c => new ComponentListItem(
                c.Id, c.Name, c.Kind,
                c.ProjectId, c.Project!.Name,
                c.Project.ClientId, c.Project.Client!.Name,
                c.Versions.Count))
            .ToListAsync(ct);
        return TypedResults.Ok((IReadOnlyList<ComponentListItem>)rows);
    }

    private static HashSet<TEnum> ParseEnumCsv<TEnum>(string? csv) where TEnum : struct, Enum
    {
        var set = new HashSet<TEnum>();
        if (string.IsNullOrWhiteSpace(csv)) return set;
        foreach (var part in csv.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (Enum.TryParse<TEnum>(part, ignoreCase: true, out var value))
            {
                set.Add(value);
            }
        }
        return set;
    }
}
