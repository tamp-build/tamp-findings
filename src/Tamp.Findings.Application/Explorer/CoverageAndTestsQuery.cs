using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Application.Explorer;

/// <summary>
/// The coverage and tests spines.
///
/// They share a class because they answer two halves of one question — what the
/// tests executed, and what they concluded — and both come from the same
/// ingested run.
/// </summary>
public sealed class CoverageAndTestsQuery
{
    private readonly FindingsDbContext _db;

    public CoverageAndTestsQuery(FindingsDbContext db) => _db = db;

    /// <summary>
    /// Coverage grouped by module, files worst-first.
    ///
    /// "Worst" is LOWEST coverage, not highest: the reader is looking for what
    /// is untested. Sorting the well-covered files to the top would bury the
    /// answer under everything that is already fine.
    /// </summary>
    public async Task<IReadOnlyList<CoverageGroup>> CoverageTreeAsync(
        Guid projectId, string? commitSha, CancellationToken ct = default)
    {
        var modules = await (
            from m in _db.CoverageModules.AsNoTracking()
            join r in _db.CoverageReports.AsNoTracking() on m.CoverageReportId equals r.Id
            join cv in _db.ComponentVersions.AsNoTracking() on r.ComponentVersionId equals cv.Id
            join c in _db.Components.AsNoTracking() on cv.ComponentId equals c.Id
            where c.ProjectId == projectId && (commitSha == null || cv.CommitSha == commitSha)
            select new { m.Id, m.Name, m.SequenceCoverage, m.CoveredSequences, m.TotalSequences })
            .ToArrayAsync(ct);

        var moduleIds = modules.Select(m => m.Id).ToArray();

        var files = await (
            from cls in _db.CoverageClasses.AsNoTracking()
            join f in _db.CoverageSourceFiles.AsNoTracking() on cls.CoverageSourceFileId equals f.Id
            where moduleIds.Contains(cls.CoverageModuleId)
            select new
            {
                cls.CoverageModuleId,
                f.RelativePath,
                Visited = cls.VisitedLines.Length,
                Unvisited = cls.UnvisitedLines.Length,
            })
            .ToArrayAsync(ct);

        return modules
            .OrderBy(m => m.SequenceCoverage)
            .Select(m => new CoverageGroup(
                m.Name,
                m.SequenceCoverage,
                files.Where(f => f.CoverageModuleId == m.Id)
                     .GroupBy(f => f.RelativePath)
                     .Select(g =>
                     {
                         var visited = g.Sum(x => x.Visited);
                         var total = visited + g.Sum(x => x.Unvisited);
                         return new CoverageLeaf(g.Key, total == 0 ? 0 : visited * 100.0 / total, total);
                     })
                     .OrderBy(l => l.Percent)
                     .ThenBy(l => l.Path, StringComparer.Ordinal)
                     .ToList()))
            .ToArray();
    }

    /// <summary>The covered/uncovered line map for one file.</summary>
    public async Task<CoverageLineMap?> CoverageDetailAsync(
        Guid projectId, string? commitSha, string relativePath, CancellationToken ct = default)
    {
        var rows = await (
            from cls in _db.CoverageClasses.AsNoTracking()
            join f in _db.CoverageSourceFiles.AsNoTracking() on cls.CoverageSourceFileId equals f.Id
            join r in _db.CoverageReports.AsNoTracking() on f.CoverageReportId equals r.Id
            join cv in _db.ComponentVersions.AsNoTracking() on r.ComponentVersionId equals cv.Id
            join c in _db.Components.AsNoTracking() on cv.ComponentId equals c.Id
            where c.ProjectId == projectId
                  && (commitSha == null || cv.CommitSha == commitSha)
                  && f.RelativePath == relativePath
            select new { f.SourceText, cls.VisitedLines, cls.UnvisitedLines })
            .ToArrayAsync(ct);

        if (rows.Length == 0) return null;

        // A file's classes each carry their own line lists; the file's map is
        // the union. A line covered by any class is covered.
        var visited = rows.SelectMany(r => r.VisitedLines).ToHashSet();
        var unvisited = rows.SelectMany(r => r.UnvisitedLines).Where(l => !visited.Contains(l)).ToHashSet();

        return new CoverageLineMap(rows[0].SourceText, visited, unvisited);
    }

    /// <summary>
    /// Test suites grouped by assembly.
    ///
    /// Ordered by failures then skips, because both are questions and passes
    /// are not. A SKIPPED TEST IS NOT A PASSING TEST — the same defect class as
    /// SSDF PW.8.1 answering "Yes" off a green run that did not exist.
    /// </summary>
    public async Task<IReadOnlyList<TestGroup>> TestTreeAsync(
        Guid projectId, string? commitSha, CancellationToken ct = default)
    {
        var suites = await (
            from s in _db.TestSuiteResults.AsNoTracking()
            join r in _db.TestRunReports.AsNoTracking() on s.TestRunReportId equals r.Id
            join cv in _db.ComponentVersions.AsNoTracking() on r.ComponentVersionId equals cv.Id
            join c in _db.Components.AsNoTracking() on cv.ComponentId equals c.Id
            where c.ProjectId == projectId && (commitSha == null || cv.CommitSha == commitSha)
            select new
            {
                s.AssemblyName, s.ClassName,
                s.TotalCount, s.PassedCount, s.FailedCount, s.SkippedCount, s.DurationMs,
            })
            .ToArrayAsync(ct);

        return suites
            .GroupBy(s => s.AssemblyName)
            .OrderByDescending(g => g.Sum(s => s.FailedCount))
            .ThenByDescending(g => g.Sum(s => s.SkippedCount))
            .ThenBy(g => g.Key, StringComparer.Ordinal)
            .Select(g => new TestGroup(
                g.Key,
                g.Sum(s => s.FailedCount),
                g.Sum(s => s.SkippedCount),
                g.Select(s => new TestLeaf(
                     s.ClassName, s.TotalCount, s.PassedCount, s.FailedCount, s.SkippedCount, s.DurationMs))
                 .OrderByDescending(s => s.Failed)
                 .ThenByDescending(s => s.Skipped)
                 .ThenBy(s => s.ClassName, StringComparer.Ordinal)
                 .ToList()))
            .ToArray();
    }

    /// <summary>
    /// Cases in one suite. Skip reasons are carried through: a skipped test
    /// with no stated reason is worth seeing as such.
    /// </summary>
    public async Task<IReadOnlyList<TestCase>> TestDetailAsync(
        Guid projectId, string? commitSha, string className, CancellationToken ct = default)
    {
        var cases = await (
            from tc in _db.TestCaseResults.AsNoTracking()
            join s in _db.TestSuiteResults.AsNoTracking() on tc.TestSuiteResultId equals s.Id
            join r in _db.TestRunReports.AsNoTracking() on s.TestRunReportId equals r.Id
            join cv in _db.ComponentVersions.AsNoTracking() on r.ComponentVersionId equals cv.Id
            join c in _db.Components.AsNoTracking() on cv.ComponentId equals c.Id
            where c.ProjectId == projectId
                  && (commitSha == null || cv.CommitSha == commitSha)
                  && s.ClassName == className
            select new TestCase(tc.Name, tc.Outcome, tc.DurationMs, tc.ErrorMessage))
            .ToArrayAsync(ct);

        return cases
            .OrderByDescending(c => c.Outcome == TestOutcome.Failed)
            .ThenByDescending(c => c.Outcome == TestOutcome.Skipped)
            .ThenBy(c => c.Name, StringComparer.Ordinal)
            .ToArray();
    }
}

public sealed record CoverageGroup(string Module, double Percent, List<CoverageLeaf> Files);

public sealed record CoverageLeaf(string Path, double Percent, int Lines);

public sealed record CoverageLineMap(string SourceText, IReadOnlySet<int> Visited, IReadOnlySet<int> Unvisited);

public sealed record TestGroup(string Assembly, int Failed, int Skipped, List<TestLeaf> Suites);

public sealed record TestLeaf(
    string ClassName, int Total, int Passed, int Failed, int Skipped, double DurationMs);

public sealed record TestCase(string Name, TestOutcome Outcome, double DurationMs, string? Note);
