using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Application.Explorer;

/// <summary>
/// The DAST spine: what a scanner found against a running deployment.
///
/// Problem 6 on the brief's list was that DAST did not fit the SAST model. It
/// has no file and no line — it has the request the scanner made — so the tree
/// groups by HOST and then by route, and the detail shows the request and the
/// response with the reflected payload as evidence.
///
/// Route identity comes from <see cref="DastRoute"/>, which FindingHasher also
/// uses. If the two disagreed, the tree would show a different set of routes
/// than dedup believes exists.
/// </summary>
public sealed class DastExplorerQuery
{
    private readonly FindingsDbContext _db;
    private readonly HostAliasService _aliases;

    public DastExplorerQuery(FindingsDbContext db, HostAliasService aliases)
    {
        _db = db;
        _aliases = aliases;
    }

    public async Task<DastTree> TreeAsync(
        Guid projectId, string? commitSha, CancellationToken ct = default)
    {
        var rows = await (
            from f in _db.Findings.AsNoTracking()
            join cv in _db.ComponentVersions.AsNoTracking() on f.ComponentVersionId equals cv.Id
            join c in _db.Components.AsNoTracking() on cv.ComponentId equals c.Id
            where c.ProjectId == projectId
                  && (commitSha == null || cv.CommitSha == commitSha)
                  && ScannerKinds.Dast.Contains(f.Scanner)
                  && f.Status == FindingStatus.Open
            select new { f.Id, f.FilePath, f.Severity, f.RuleId, f.Title, f.Scanner })
            .ToArrayAsync(ct);

        var aliases = await _aliases.ForProjectAsync(projectId, ct);

        var hosts = rows
            .GroupBy(r => aliases.Canonical(DastRoute.HostOf(r.FilePath)))
            .OrderBy(g => g.Key, StringComparer.Ordinal)
            .Select(g => new DastHost(
                g.Key,
                g.GroupBy(r =>
                    {
                        var (path, parameters) = DastRoute.Normalize(r.FilePath);
                        return DastRoute.Display(path, parameters);
                    })
                 .Select(routes => new DastRouteRow(
                     routes.Key,
                     routes.Max(r => r.Severity),
                     routes.Count()))
                 .OrderByDescending(r => r.WorstSeverity)
                 .ThenBy(r => r.Route, StringComparer.Ordinal)
                 .ToList()))
            .ToArray();

        // Hosts that look like the same application reached two ways. The
        // callout exists because findings are attributed to HOW THE SCANNER
        // CONNECTED rather than to the application — problem 7 on the brief's
        // list, "one app appearing as two hosts".
        var duplicates = aliases.SuspectedDuplicates(hosts.Select(h => h.Host).ToArray());

        return new DastTree(hosts, duplicates);
    }

    /// <summary>
    /// The findings on one route, with their request/response evidence.
    ///
    /// The evidence is what makes a DAST finding actionable: a reflected
    /// payload in the response is the difference between "a scanner said so"
    /// and "here is the proof".
    /// </summary>
    public async Task<IReadOnlyList<DastFinding>> DetailAsync(
        Guid projectId, string? commitSha, string route, CancellationToken ct = default)
    {
        var rows = await (
            from f in _db.Findings.AsNoTracking()
            join cv in _db.ComponentVersions.AsNoTracking() on f.ComponentVersionId equals cv.Id
            join c in _db.Components.AsNoTracking() on cv.ComponentId equals c.Id
            where c.ProjectId == projectId
                  && (commitSha == null || cv.CommitSha == commitSha)
                  && ScannerKinds.Dast.Contains(f.Scanner)
                  && f.Status == FindingStatus.Open
            select new { f.Id, f.FilePath, f.Severity, f.RuleId, f.Title, f.Description, f.Snippet, f.Scanner })
            .ToArrayAsync(ct);

        return rows
            .Where(r =>
            {
                var (path, parameters) = DastRoute.Normalize(r.FilePath);
                return DastRoute.Display(path, parameters) == route;
            })
            .OrderByDescending(r => r.Severity)
            .Select(r => new DastFinding(
                r.Id, r.RuleId, r.Severity, r.Title, r.Description,
                r.FilePath, SplitEvidence(r.Snippet), r.Scanner))
            .ToArray();
    }

    /// <summary>
    /// Scanners pack request and response into one blob. Splitting them lets
    /// the detail show them side by side, which is how a reader spots the
    /// payload echoed back.
    ///
    /// Falls back to putting everything in the response pane rather than
    /// guessing: showing the whole blob is honest, inventing a split is not.
    /// </summary>
    private static DastEvidence SplitEvidence(string? snippet)
    {
        if (string.IsNullOrWhiteSpace(snippet)) return new DastEvidence(null, null);

        var normalised = snippet.Replace("\r\n", "\n");

        // A blank line separates headers from body within each half, and
        // scanners conventionally separate the two halves with a marker or a
        // double blank line.
        var markers = new[] { "\n\nHTTP/", "\n\n\n" };
        foreach (var marker in markers)
        {
            var index = normalised.IndexOf(marker, StringComparison.Ordinal);
            if (index > 0)
            {
                return new DastEvidence(
                    normalised[..index].Trim(),
                    normalised[index..].Trim());
            }
        }

        return new DastEvidence(null, normalised.Trim());
    }
}

public sealed record DastTree(IReadOnlyList<DastHost> Hosts, IReadOnlyList<DuplicateHostSuspicion> Duplicates);

public sealed record DastHost(string Host, List<DastRouteRow> Routes);

public sealed record DastRouteRow(string Route, Severity WorstSeverity, int Count);

public sealed record DastEvidence(string? Request, string? Response);

public sealed record DastFinding(
    Guid Id, string RuleId, Severity Severity, string Title, string? Description,
    string? TargetUrl, DastEvidence Evidence, ScannerKind Scanner);
