using System.Xml.Linq;
using Tamp.Findings.Build.Ingest;

namespace Tamp.Findings.Build.Adapters;

// Walks every coverage.opencover.xml under artifacts/test-results and folds
// them into one ingest payload — modules, per-class line maps, deduped
// source-file bodies. Multiple test projects can overlap (both tests instrument
// the shared Domain assembly), so we union visited-line sets per class.
public static class CoverageIngestMapper
{
    public static CoverageIngestRequestDto? Map(string testResultsRoot, IngestBuildContext ctx, string repoRoot)
    {
        if (!Directory.Exists(testResultsRoot)) return null;
        var xmls = Directory.EnumerateFiles(testResultsRoot, "coverage.opencover.xml", SearchOption.AllDirectories).ToList();
        if (xmls.Count == 0) return null;

        long totalSeq = 0, coveredSeq = 0, totalBr = 0, coveredBr = 0;

        // Per-module aggregates (across XMLs).
        var moduleAcc = new Dictionary<string, ModuleAcc>(StringComparer.OrdinalIgnoreCase);

        foreach (var xmlPath in xmls)
        {
            XDocument doc;
            try { doc = XDocument.Load(xmlPath); }
            catch { continue; }

            var session = doc.Root;
            if (session is null || session.Name.LocalName != "CoverageSession") continue;

            foreach (var moduleEl in session.Element("Modules")?.Elements("Module") ?? Enumerable.Empty<XElement>())
            {
                var moduleName = (string?)moduleEl.Element("ModuleName");
                if (string.IsNullOrWhiteSpace(moduleName)) continue;
                if (IsTestOrTransient(moduleName)) continue;

                // File uid → absolute path lookup for this module.
                var fileLookup = (moduleEl.Element("Files")?.Elements("File") ?? Enumerable.Empty<XElement>())
                    .ToDictionary(
                        f => (string?)f.Attribute("uid") ?? "",
                        f => (string?)f.Attribute("fullPath") ?? "",
                        StringComparer.OrdinalIgnoreCase);

                if (!moduleAcc.TryGetValue(moduleName, out var mAcc))
                {
                    mAcc = new ModuleAcc();
                    moduleAcc[moduleName] = mAcc;
                }

                foreach (var classEl in moduleEl.Element("Classes")?.Elements("Class") ?? Enumerable.Empty<XElement>())
                {
                    var className = (string?)classEl.Element("FullName") ?? "";
                    if (string.IsNullOrWhiteSpace(className)) continue;
                    // Compiler-generated noise: <PrivateImplementationDetails>,
                    // <>c, <>c__DisplayClass*, lambda hosts. They're real but
                    // not useful in a Test Explorer-style view.
                    if (IsCompilerGenerated(className)) continue;

                    var classSummary = classEl.Element("Summary");
                    if (classSummary is null) continue;
                    var (cTotal, cCovered) = ReadSeq(classSummary);
                    var (cTotalBr, cCoveredBr) = ReadBr(classSummary);

                    // Group methods by their FileRef so partial classes split
                    // into (class, file) rows.
                    var methodsByFile = new Dictionary<string, List<XElement>>();
                    foreach (var method in classEl.Element("Methods")?.Elements("Method") ?? Enumerable.Empty<XElement>())
                    {
                        var fileUid = (string?)method.Element("FileRef")?.Attribute("uid") ?? "";
                        if (string.IsNullOrWhiteSpace(fileUid)) continue;
                        if (!methodsByFile.TryGetValue(fileUid, out var lst))
                        {
                            lst = [];
                            methodsByFile[fileUid] = lst;
                        }
                        lst.Add(method);
                    }

                    foreach (var (fileUid, methods) in methodsByFile)
                    {
                        if (!fileLookup.TryGetValue(fileUid, out var absPath) || string.IsNullOrWhiteSpace(absPath)) continue;
                        var relPath = NormaliseRelativePath(absPath, repoRoot);

                        var classKey = $"{className}|{relPath}";
                        if (!mAcc.Classes.TryGetValue(classKey, out var cAcc))
                        {
                            cAcc = new ClassAcc
                            {
                                FullName = className,
                                RelativePath = relPath,
                                AbsolutePath = absPath,
                            };
                            mAcc.Classes[classKey] = cAcc;
                        }

                        // Aggregate this (class, file) bucket's seq/branch totals
                        // from the methods. Class-level Summary covers the whole
                        // class (across files), so we recompute per-bucket from
                        // method Summaries.
                        long bTotal = 0, bCovered = 0, bTotalBr = 0, bCoveredBr = 0;
                        foreach (var method in methods)
                        {
                            var mSum = method.Element("Summary");
                            if (mSum != null)
                            {
                                var (mt, mc) = ReadSeq(mSum);
                                var (mtb, mcb) = ReadBr(mSum);
                                bTotal += mt; bCovered += mc; bTotalBr += mtb; bCoveredBr += mcb;
                            }
                            foreach (var sp in method.Element("SequencePoints")?.Elements("SequencePoint") ?? Enumerable.Empty<XElement>())
                            {
                                var sl = (int?)sp.Attribute("sl");
                                var el = (int?)sp.Attribute("el") ?? sl;
                                var vc = (int?)sp.Attribute("vc") ?? 0;
                                if (sl is null) continue;
                                for (var line = sl.Value; line <= (el ?? sl.Value); line++)
                                {
                                    if (vc > 0) cAcc.Visited.Add(line);
                                    else cAcc.Unvisited.Add(line);
                                }
                            }
                        }
                        cAcc.TotalSequences += (int)bTotal;
                        cAcc.CoveredSequences += (int)bCovered;
                        cAcc.TotalBranches += (int)bTotalBr;
                        cAcc.CoveredBranches += (int)bCoveredBr;
                    }

                    // Module-level totals for the parent CoverageReport.
                    mAcc.TotalSequences += (int)cTotal;
                    mAcc.CoveredSequences += (int)cCovered;
                    mAcc.TotalBranches += (int)cTotalBr;
                    mAcc.CoveredBranches += (int)cCoveredBr;
                    totalSeq += cTotal; coveredSeq += cCovered;
                    totalBr += cTotalBr; coveredBr += cCoveredBr;
                }
            }
        }

        if (totalSeq == 0 && moduleAcc.Count == 0) return null;

        // A line covered by one test project but not another → covered overall.
        foreach (var mAcc in moduleAcc.Values)
        {
            foreach (var cAcc in mAcc.Classes.Values)
            {
                cAcc.Unvisited.ExceptWith(cAcc.Visited);
            }
        }

        var modules = moduleAcc
            .Select(kv => new CoverageModuleDto(
                Name: kv.Key,
                SequenceCoverage: kv.Value.TotalSequences == 0 ? 0 : 100.0 * kv.Value.CoveredSequences / kv.Value.TotalSequences,
                BranchCoverage: kv.Value.TotalBranches == 0 ? 0 : 100.0 * kv.Value.CoveredBranches / kv.Value.TotalBranches,
                CoveredSequences: kv.Value.CoveredSequences,
                TotalSequences: kv.Value.TotalSequences,
                Classes: kv.Value.Classes.Values
                    .Select(c => new CoverageClassDto(
                        FullName: c.FullName,
                        SourceFileRelativePath: c.RelativePath,
                        SequenceCoverage: c.TotalSequences == 0 ? 0 : 100.0 * c.CoveredSequences / c.TotalSequences,
                        BranchCoverage: c.TotalBranches == 0 ? 0 : 100.0 * c.CoveredBranches / c.TotalBranches,
                        CoveredSequences: c.CoveredSequences,
                        TotalSequences: c.TotalSequences,
                        CoveredBranches: c.CoveredBranches,
                        TotalBranches: c.TotalBranches,
                        VisitedLines: c.Visited.OrderBy(x => x).ToArray(),
                        UnvisitedLines: c.Unvisited.OrderBy(x => x).ToArray()))
                    .OrderBy(c => c.FullName, StringComparer.OrdinalIgnoreCase)
                    .ToList()))
            .OrderBy(m => m.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();

        // Build unique source-file payload, reading from disk at scan time so
        // the dashboard never depends on the build host's filesystem at view time.
        var sourceFiles = new List<CoverageSourceFileDto>();
        var seenPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var mAcc in moduleAcc.Values)
        {
            foreach (var cAcc in mAcc.Classes.Values)
            {
                if (!seenPaths.Add(cAcc.RelativePath)) continue;
                string source = "";
                try
                {
                    if (File.Exists(cAcc.AbsolutePath))
                    {
                        source = File.ReadAllText(cAcc.AbsolutePath);
                    }
                }
                catch
                {
                    // Source files outside the build host or with permission issues
                    // get an empty body — the SPA still renders the line map, just
                    // without code content.
                }
                sourceFiles.Add(new CoverageSourceFileDto(
                    RelativePath: cAcc.RelativePath,
                    AbsolutePath: cAcc.AbsolutePath,
                    SourceText: source));
            }
        }

        return new CoverageIngestRequestDto(
            Client: ctx.Client,
            Project: ctx.Project,
            Component: ctx.Component,
            ComponentKind: ctx.ComponentKind,
            Flavor: ctx.Flavor,
            Version: ctx.Version,
            CommitSha: ctx.CommitSha,
            Branch: ctx.Branch,
            BuildId: ctx.BuildId,
            PullRequestRef: ctx.PullRequestRef,
            ToolName: "Coverlet",
            ToolVersion: null,
            SequenceCoverage: totalSeq == 0 ? 0 : 100.0 * coveredSeq / totalSeq,
            BranchCoverage: totalBr == 0 ? 0 : 100.0 * coveredBr / totalBr,
            CoveredSequences: (int)coveredSeq,
            TotalSequences: (int)totalSeq,
            CoveredBranches: (int)coveredBr,
            TotalBranches: (int)totalBr,
            Modules: modules,
            SourceFiles: sourceFiles);
    }

    private static string NormaliseRelativePath(string absolutePath, string repoRoot)
    {
        try
        {
            var rel = Path.GetRelativePath(repoRoot, absolutePath);
            // Keep forward slashes — Postgres index and SPA paths both prefer them.
            return rel.Replace('\\', '/');
        }
        catch
        {
            return absolutePath;
        }
    }

    private static bool IsTestOrTransient(string moduleName)
    {
        if (moduleName.EndsWith(".Tests", StringComparison.OrdinalIgnoreCase)) return true;
        if (moduleName.Contains(".Tests.", StringComparison.OrdinalIgnoreCase)) return true;
        if (moduleName.StartsWith("xunit.", StringComparison.OrdinalIgnoreCase)) return true;
        if (moduleName.StartsWith("Moq", StringComparison.OrdinalIgnoreCase)) return true;
        if (moduleName.StartsWith("Microsoft.TestPlatform.", StringComparison.OrdinalIgnoreCase)) return true;
        if (moduleName.StartsWith("testhost", StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    private static bool IsCompilerGenerated(string className)
    {
        // Lambda-host display classes, anonymous types, async state machines,
        // <PrivateImplementationDetails>, etc. These pollute the Test Explorer
        // tree without giving the user a meaningful "click into the code" target.
        if (className.Contains("<>c", StringComparison.Ordinal)) return true;
        if (className.Contains("<PrivateImplementationDetails>", StringComparison.Ordinal)) return true;
        if (className.Contains("d__", StringComparison.Ordinal) && className.Contains("<", StringComparison.Ordinal)) return true;
        return false;
    }

    private static (long Total, long Covered) ReadSeq(XElement summary)
    {
        long total = (long?)summary.Attribute("numSequencePoints") ?? 0;
        long covered = (long?)summary.Attribute("visitedSequencePoints") ?? 0;
        return (total, covered);
    }

    private static (long Total, long Covered) ReadBr(XElement summary)
    {
        long total = (long?)summary.Attribute("numBranchPoints") ?? 0;
        long covered = (long?)summary.Attribute("visitedBranchPoints") ?? 0;
        return (total, covered);
    }

    private sealed class ModuleAcc
    {
        public int TotalSequences { get; set; }
        public int CoveredSequences { get; set; }
        public int TotalBranches { get; set; }
        public int CoveredBranches { get; set; }
        public Dictionary<string, ClassAcc> Classes { get; } = new(StringComparer.OrdinalIgnoreCase);
    }

    private sealed class ClassAcc
    {
        public string FullName { get; set; } = "";
        public string RelativePath { get; set; } = "";
        public string AbsolutePath { get; set; } = "";
        public int TotalSequences { get; set; }
        public int CoveredSequences { get; set; }
        public int TotalBranches { get; set; }
        public int CoveredBranches { get; set; }
        public HashSet<int> Visited { get; } = new();
        public HashSet<int> Unvisited { get; } = new();
    }
}

public sealed record CoverageIngestRequestDto(
    string Client,
    string Project,
    string Component,
    string? ComponentKind,
    string? Flavor,
    string Version,
    string? CommitSha,
    string? Branch,
    string? BuildId,
    string? PullRequestRef,
    string ToolName,
    string? ToolVersion,
    double SequenceCoverage,
    double BranchCoverage,
    int CoveredSequences,
    int TotalSequences,
    int CoveredBranches,
    int TotalBranches,
    IReadOnlyList<CoverageModuleDto> Modules,
    IReadOnlyList<CoverageSourceFileDto> SourceFiles);

public sealed record CoverageModuleDto(
    string Name,
    double SequenceCoverage,
    double BranchCoverage,
    int CoveredSequences,
    int TotalSequences,
    IReadOnlyList<CoverageClassDto> Classes);

public sealed record CoverageClassDto(
    string FullName,
    string SourceFileRelativePath,
    double SequenceCoverage,
    double BranchCoverage,
    int CoveredSequences,
    int TotalSequences,
    int CoveredBranches,
    int TotalBranches,
    int[] VisitedLines,
    int[] UnvisitedLines);

public sealed record CoverageSourceFileDto(
    string RelativePath,
    string? AbsolutePath,
    string SourceText);
