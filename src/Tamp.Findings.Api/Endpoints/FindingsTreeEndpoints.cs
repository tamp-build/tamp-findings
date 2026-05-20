using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Api.Contracts;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Api.Endpoints;

// Read endpoints powering the file-tree Findings view (the SAST detail
// surface that mirrors CoverageView):
//   GET /findings/tree            — module → file groups with severity counts
//   GET /findings/file?path=...   — source text + findings landing on that file
//
// Path normalisation: scanners emit FilePath inconsistently. Roslyn ships
// "file:///C:/repos/tamp.findings/src/...", ReSharper ships clean repo-
// relative paths like "src/...". Both fold here to a single relative form
// keyed against CoverageSourceFile.RelativePath so source lookup works.
public static class FindingsTreeEndpoints
{
    public static IEndpointRouteBuilder MapFindingsTree(this IEndpointRouteBuilder app)
    {
        app.MapGet("/findings/tree", GetTreeAsync)
           .WithName("GetFindingsTree")
           .WithSummary("Module → file tree of open findings with severity counts. Scope filters mirror /aggregates.");
        app.MapGet("/findings/file", GetFileAsync)
           .WithName("GetFindingsFile")
           .WithSummary("Source text + all findings on the given repo-relative file path.");
        return app;
    }

    private static async Task<IResult> GetTreeAsync(
        FindingsDbContext db,
        CancellationToken ct,
        Guid? clientId = null,
        Guid? projectId = null,
        Guid? componentId = null,
        string? ruleId = null,
        bool latest = true)
    {
        var ids = await ScopedFindingsAsync(db, clientId, projectId, componentId, latest, ruleId, ct);
        if (ids.Count == 0)
        {
            return Results.Ok(new FindingsTreeResponse(
                TotalCount: 0,
                Counts: ZeroCounts(),
                Modules: [],
                NoPathCount: 0));
        }

        var rows = await db.Findings.AsNoTracking()
            .Where(f => ids.Contains(f.Id))
            .Select(f => new { f.Severity, f.FilePath })
            .ToListAsync(ct);

        // Group by (module, normalisedPath). Findings without a usable path
        // collapse into NoPathCount and never appear in the tree.
        var noPath = 0;
        var byFile = new Dictionary<string, FileAcc>(StringComparer.OrdinalIgnoreCase);
        foreach (var r in rows)
        {
            var normalised = NormalisePath(r.FilePath);
            if (string.IsNullOrWhiteSpace(normalised))
            {
                noPath++;
                continue;
            }
            if (!byFile.TryGetValue(normalised, out var acc))
            {
                acc = new FileAcc { Module = DeriveModule(normalised), Path = normalised };
                byFile[normalised] = acc;
            }
            acc.Bump(r.Severity);
        }

        var modules = byFile.Values
            .GroupBy(f => f.Module, StringComparer.OrdinalIgnoreCase)
            .Select(g => new FindingsTreeModuleDto(
                Name: g.Key,
                Counts: SumCounts(g.Select(f => f.Counts)),
                Files: g
                    .OrderByDescending(f => SeverityRank(f.MaxSeverity))
                    .ThenBy(f => f.Path, StringComparer.OrdinalIgnoreCase)
                    .Select(f => new FindingsTreeFileDto(
                        RelativePath: f.Path,
                        Counts: f.Counts,
                        MaxSeverity: f.MaxSeverity))
                    .ToList()))
            .OrderByDescending(m => m.Counts.Total)
            .ThenBy(m => m.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var overall = SumCounts(modules.Select(m => m.Counts));
        return Results.Ok(new FindingsTreeResponse(
            TotalCount: overall.Total + noPath,
            Counts: overall,
            Modules: modules,
            NoPathCount: noPath));
    }

    private static async Task<IResult> GetFileAsync(
        string path,
        FindingsDbContext db,
        CancellationToken ct,
        Guid? clientId = null,
        Guid? projectId = null,
        Guid? componentId = null,
        string? ruleId = null,
        bool latest = true)
    {
        if (string.IsNullOrWhiteSpace(path)) return Results.BadRequest("path is required");

        // Look up source from CoverageSourceFile — same path key as the
        // coverage detail view, but unscoped (any report's copy of the file
        // is fine; the text is what the user wrote at the canonical revision).
        var source = await db.CoverageSourceFiles.AsNoTracking()
            .Where(f => f.RelativePath == path)
            .OrderByDescending(f => f.Id)
            .FirstOrDefaultAsync(ct);

        var ids = await ScopedFindingsAsync(db, clientId, projectId, componentId, latest, ruleId, ct);
        var findings = await db.Findings.AsNoTracking()
            .Where(f => ids.Contains(f.Id))
            .Select(f => new { f.Id, f.Scanner, f.RuleId, f.Severity, f.Title, f.Description, f.FilePath, f.Line, f.Status })
            .ToListAsync(ct);
        var hits = findings
            .Where(f => string.Equals(NormalisePath(f.FilePath), path, StringComparison.OrdinalIgnoreCase))
            .OrderBy(f => f.Line ?? 0)
            .ThenByDescending(f => SeverityRank(f.Severity))
            .Select(f => new FindingsFileItemDto(
                f.Id, f.Scanner, f.RuleId, f.Severity, f.Title, f.Description, f.Line))
            .ToList();

        return Results.Ok(new FindingsFileResponse(
            RelativePath: path,
            SourceAvailable: source is not null,
            SourceText: source?.SourceText ?? "",
            Findings: hits));
    }

    private sealed class FileAcc
    {
        public string Module { get; set; } = "";
        public string Path { get; set; } = "";
        public SeverityCounts Counts { get; set; } = ZeroCounts();
        public Severity MaxSeverity { get; set; } = Severity.Info;

        public void Bump(Severity s)
        {
            var c = Counts;
            Counts = s switch
            {
                Severity.Critical => c with { Critical = c.Critical + 1 },
                Severity.High     => c with { High     = c.High + 1 },
                Severity.Medium   => c with { Medium   = c.Medium + 1 },
                Severity.Low      => c with { Low      = c.Low + 1 },
                _                 => c with { Info     = c.Info + 1 },
            };
            if (SeverityRank(s) > SeverityRank(MaxSeverity)) MaxSeverity = s;
        }
    }

    private static SeverityCounts SumCounts(IEnumerable<SeverityCounts> source)
    {
        int c = 0, h = 0, m = 0, l = 0, i = 0;
        foreach (var s in source) { c += s.Critical; h += s.High; m += s.Medium; l += s.Low; i += s.Info; }
        return new SeverityCounts(Info: i, Low: l, Medium: m, High: h, Critical: c);
    }

    private static SeverityCounts ZeroCounts() => new(Info: 0, Low: 0, Medium: 0, High: 0, Critical: 0);

    private static int SeverityRank(Severity s) => s switch
    {
        Severity.Critical => 4,
        Severity.High => 3,
        Severity.Medium => 2,
        Severity.Low => 1,
        _ => 0,
    };

    // Roslyn SARIF stores absolute file:/// URIs; ReSharper SARIF stores
    // clean repo-relative paths. Both normalise here to repo-relative.
    // Detection is path-pattern based: anything containing "/src/" or
    // "/web/" or "/build/" gets sliced from that segment onward.
    private static string NormalisePath(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return "";
        var s = raw.Trim();
        if (s.StartsWith("file:///", StringComparison.OrdinalIgnoreCase)) s = s[8..];
        s = s.Replace('\\', '/');
        // Find /repos/<anything>/src|web|build/ and slice from src/web/build.
        foreach (var anchor in new[] { "/src/", "/web/", "/build/" })
        {
            var idx = s.IndexOf(anchor, StringComparison.OrdinalIgnoreCase);
            if (idx >= 0) return s[(idx + 1)..];
        }
        return s;
    }

    private static string DeriveModule(string normalisedPath)
    {
        var parts = normalisedPath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length >= 2 && parts[0].Equals("src", StringComparison.OrdinalIgnoreCase)) return parts[1];
        if (parts.Length >= 1 && parts[0].Equals("web", StringComparison.OrdinalIgnoreCase)) return "web";
        if (parts.Length >= 1 && parts[0].Equals("build", StringComparison.OrdinalIgnoreCase)) return "build";
        return "(other)";
    }

    private static async Task<List<Guid>> ScopedFindingsAsync(
        FindingsDbContext db,
        Guid? clientId,
        Guid? projectId,
        Guid? componentId,
        bool latest,
        string? ruleId,
        CancellationToken ct)
    {
        var q = db.Findings.AsNoTracking().Where(f => f.Status == FindingStatus.Open);
        if (componentId is { } cmp) q = q.Where(f => f.ComponentVersion!.ComponentId == cmp);
        if (projectId is { } prj) q = q.Where(f => f.ComponentVersion!.Component!.ProjectId == prj);
        if (clientId is { } cli) q = q.Where(f => f.ComponentVersion!.Component!.Project!.ClientId == cli);
        if (!string.IsNullOrWhiteSpace(ruleId)) q = q.Where(f => f.RuleId == ruleId);
        if (latest)
        {
            var latestCvIds = await db.ComponentVersions
                .GroupBy(v => new { v.ComponentId, FlavorKey = v.FlavorId ?? Guid.Empty })
                .Select(g => g.OrderByDescending(v => v.CreatedAt).First().Id)
                .ToListAsync(ct);
            q = q.Where(f => latestCvIds.Contains(f.ComponentVersionId));
        }
        return await q.Select(f => f.Id).ToListAsync(ct);
    }
}
