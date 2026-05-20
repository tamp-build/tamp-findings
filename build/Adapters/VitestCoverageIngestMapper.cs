using Tamp.Findings.Build.Ingest;

namespace Tamp.Findings.Build.Adapters;

// Parses Vitest's lcov.info (emitted by @vitest/coverage-v8) into the same
// CoverageIngestRequestDto shape we use for .NET / Coverlet output. Map:
//   SF:<path>   → start of file (one CoverageClass per file)
//   DA:<l>,<n>  → per-line hit count; n>0 = visited
//   BRDA:l,b,br,taken → branch coverage
//
// SPA has no real "module" the way .NET assemblies do, so everything rolls
// into a single module called "web". The "class FullName" is the file's
// repo-relative path, which is what the CoverageView tree renders.
public static class VitestCoverageIngestMapper
{
    public static CoverageIngestRequestDto? Map(string lcovPath, IngestBuildContext ctx, string repoRoot, string spaProjectDir)
    {
        if (!File.Exists(lcovPath)) return null;
        var lines = File.ReadAllLines(lcovPath);

        // Path lcov emits is relative to the vitest run directory (web/). To
        // present a stable repo-relative path on the dashboard we prepend the
        // SPA project directory's name.
        var spaProjectName = Path.GetFileName(spaProjectDir.TrimEnd('/', '\\'));

        var files = new List<LcovFile>();
        LcovFile? current = null;

        foreach (var raw in lines)
        {
            var line = raw.Trim();
            if (line.StartsWith("SF:"))
            {
                if (current is not null) files.Add(current);
                var sfPath = line[3..].Trim().Replace('\\', '/');
                current = new LcovFile(sfPath);
            }
            else if (current is null)
            {
                continue;
            }
            else if (line.StartsWith("DA:"))
            {
                // DA:<line>,<hit>[,<checksum>]
                var parts = line[3..].Split(',');
                if (parts.Length >= 2
                    && int.TryParse(parts[0], out var ln)
                    && int.TryParse(parts[1], out var hit))
                {
                    if (hit > 0) current.Visited.Add(ln);
                    else current.Unvisited.Add(ln);
                }
            }
            else if (line.StartsWith("BRDA:"))
            {
                // BRDA:<line>,<block>,<branch>,<taken|->
                var parts = line[5..].Split(',');
                if (parts.Length >= 4)
                {
                    var taken = parts[3];
                    current.BranchTotal++;
                    if (taken != "-" && taken != "0") current.BranchCovered++;
                }
            }
            else if (line == "end_of_record")
            {
                files.Add(current);
                current = null;
            }
        }
        if (current is not null) files.Add(current);

        if (files.Count == 0) return null;

        // Lines hit and missed don't overlap in lcov, but defensive: visited wins.
        foreach (var f in files) f.Unvisited.ExceptWith(f.Visited);

        var classes = new List<CoverageClassDto>();
        var sourceFiles = new List<CoverageSourceFileDto>();
        var seenPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        long totalSeq = 0, coveredSeq = 0, totalBr = 0, coveredBr = 0;

        foreach (var f in files)
        {
            // Build the repo-relative path: lcov already gave us src/...,
            // we prefix with the SPA project folder name (web/).
            var relPath = $"{spaProjectName}/{f.Path}".Replace('\\', '/');
            // The absolute path on disk (in the build host) lives under repoRoot.
            var absPath = Path.GetFullPath(Path.Combine(repoRoot, relPath));

            var t = f.Visited.Count + f.Unvisited.Count;
            var c = f.Visited.Count;
            totalSeq += t;
            coveredSeq += c;
            totalBr += f.BranchTotal;
            coveredBr += f.BranchCovered;

            classes.Add(new CoverageClassDto(
                FullName: relPath,
                SourceFileRelativePath: relPath,
                SequenceCoverage: t == 0 ? 0 : 100.0 * c / t,
                BranchCoverage: f.BranchTotal == 0 ? 0 : 100.0 * f.BranchCovered / f.BranchTotal,
                CoveredSequences: c,
                TotalSequences: t,
                CoveredBranches: f.BranchCovered,
                TotalBranches: f.BranchTotal,
                VisitedLines: f.Visited.OrderBy(x => x).ToArray(),
                UnvisitedLines: f.Unvisited.OrderBy(x => x).ToArray()));

            if (!seenPaths.Add(relPath)) continue;
            string source = "";
            try { if (File.Exists(absPath)) source = File.ReadAllText(absPath); }
            catch { /* empty body still renders the line map */ }
            sourceFiles.Add(new CoverageSourceFileDto(
                RelativePath: relPath,
                AbsolutePath: absPath,
                SourceText: source));
        }

        var module = new CoverageModuleDto(
            Name: spaProjectName,
            SequenceCoverage: totalSeq == 0 ? 0 : 100.0 * coveredSeq / totalSeq,
            BranchCoverage: totalBr == 0 ? 0 : 100.0 * coveredBr / totalBr,
            CoveredSequences: (int)coveredSeq,
            TotalSequences: (int)totalSeq,
            Classes: classes.OrderBy(c => c.FullName, StringComparer.OrdinalIgnoreCase).ToList());

        return new CoverageIngestRequestDto(
            Client: ctx.Client,
            Project: ctx.Project,
            Component: ctx.Component,
            ComponentKind: ctx.ComponentKind,
            Flavor: "web",      // separate ComponentVersion from the net10 flavor
            Version: ctx.Version,
            CommitSha: ctx.CommitSha,
            Branch: ctx.Branch,
            BuildId: ctx.BuildId,
            PullRequestRef: ctx.PullRequestRef,
            ToolName: "Vitest",
            ToolVersion: null,
            SequenceCoverage: totalSeq == 0 ? 0 : 100.0 * coveredSeq / totalSeq,
            BranchCoverage: totalBr == 0 ? 0 : 100.0 * coveredBr / totalBr,
            CoveredSequences: (int)coveredSeq,
            TotalSequences: (int)totalSeq,
            CoveredBranches: (int)coveredBr,
            TotalBranches: (int)totalBr,
            Modules: [module],
            SourceFiles: sourceFiles);
    }

    private sealed class LcovFile(string path)
    {
        public string Path { get; } = path;
        public HashSet<int> Visited { get; } = new();
        public HashSet<int> Unvisited { get; } = new();
        public int BranchTotal { get; set; }
        public int BranchCovered { get; set; }
    }
}
