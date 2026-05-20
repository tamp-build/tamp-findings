using System.Xml.Linq;
using Tamp.Findings.Build.Ingest;

namespace Tamp.Findings.Build.Adapters;

// Walks every coverage.opencover.xml under artifacts/test-results and folds
// them into one ingest payload — modules, per-class line maps, deduped
// source-file bodies.
//
// Coverlet emits the same total-sequence-point count in every XML for a
// given assembly (the IL didn't change between test projects), so summing
// across XMLs double-counts. We identify every sequence/branch point by its
// (file, sl, sc, el, ec[, offset, order]) source position so the same SP
// across N XMLs becomes one row — visited = OR across XMLs, total = the
// stable count from any single XML. Visited *line* sets also union, which
// is correct for the red/green source viewer.
public static class CoverageIngestMapper
{
    public static CoverageIngestRequestDto? Map(string testResultsRoot, IngestBuildContext ctx, string repoRoot)
    {
        if (!Directory.Exists(testResultsRoot)) return null;
        var xmls = Directory.EnumerateFiles(testResultsRoot, "coverage.opencover.xml", SearchOption.AllDirectories).ToList();
        if (xmls.Count == 0) return null;

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
                    var rawClassName = (string?)classEl.Element("FullName") ?? "";
                    if (string.IsNullOrWhiteSpace(rawClassName)) continue;
                    // Drop <PrivateImplementationDetails> entirely — never user code.
                    if (rawClassName.Contains("<PrivateImplementationDetails>", StringComparison.Ordinal)) continue;
                    // Fold compiler-generated nested types (async state machines
                    // <MethodName>d__N, iterator <MethodName>d, lambda host <>c
                    // and <>c__DisplayClass*) back into the parent class. Their
                    // SequencePoints reference the original method's source
                    // lines, so attributing them to the parent gives the tree
                    // view what the user actually wrote: one row per real
                    // class, with that class's full method coverage.
                    var className = FoldNestedCompilerArtifact(rawClassName);

                    foreach (var method in classEl.Element("Methods")?.Elements("Method") ?? Enumerable.Empty<XElement>())
                    {
                        var fileUid = (string?)method.Element("FileRef")?.Attribute("uid") ?? "";
                        if (string.IsNullOrWhiteSpace(fileUid)) continue;
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

                        var methodName = (string?)method.Element("Name") ?? "";
                        if (!cAcc.Methods.TryGetValue(methodName, out var methAcc))
                        {
                            methAcc = new MethodAcc();
                            cAcc.Methods[methodName] = methAcc;
                        }

                        foreach (var sp in method.Element("SequencePoints")?.Elements("SequencePoint") ?? Enumerable.Empty<XElement>())
                        {
                            var sl = (int?)sp.Attribute("sl");
                            var sc = (int?)sp.Attribute("sc") ?? 0;
                            var el = (int?)sp.Attribute("el") ?? sl;
                            var ec = (int?)sp.Attribute("ec") ?? 0;
                            var vc = (int?)sp.Attribute("vc") ?? 0;
                            if (sl is null) continue;
                            var key = new SpKey(sl.Value, sc, el ?? sl.Value, ec);
                            if (vc > 0)
                                methAcc.SeqPoints[key] = true;
                            else if (!methAcc.SeqPoints.ContainsKey(key))
                                methAcc.SeqPoints[key] = false;

                            for (var line = sl.Value; line <= (el ?? sl.Value); line++)
                            {
                                if (vc > 0) cAcc.Visited.Add(line);
                                else cAcc.Unvisited.Add(line);
                            }
                        }

                        foreach (var bp in method.Element("BranchPoints")?.Elements("BranchPoint") ?? Enumerable.Empty<XElement>())
                        {
                            var sl = (int?)bp.Attribute("sl");
                            var sc = (int?)bp.Attribute("sc") ?? 0;
                            var el = (int?)bp.Attribute("el") ?? sl;
                            var ec = (int?)bp.Attribute("ec") ?? 0;
                            var offset = (int?)bp.Attribute("offset") ?? 0;
                            var order = (int?)bp.Attribute("ordinal") ?? 0;
                            var vc = (int?)bp.Attribute("vc") ?? 0;
                            if (sl is null) continue;
                            var key = new BpKey(sl.Value, sc, el ?? sl.Value, ec, offset, order);
                            if (vc > 0)
                                methAcc.BranchPoints[key] = true;
                            else if (!methAcc.BranchPoints.ContainsKey(key))
                                methAcc.BranchPoints[key] = false;
                        }
                    }
                }
            }
        }

        // A line visited by any test in any XML is "visited" overall; ExceptWith
        // ensures Unvisited only contains lines that were never reached.
        foreach (var mAcc in moduleAcc.Values)
        {
            foreach (var cAcc in mAcc.Classes.Values)
            {
                cAcc.Unvisited.ExceptWith(cAcc.Visited);
            }
        }

        if (moduleAcc.Count == 0) return null;

        // Bottom-up roll-ups now compute against deduped per-SP / per-branch maps.
        long rootTotalSeq = 0, rootCoveredSeq = 0, rootTotalBr = 0, rootCoveredBr = 0;
        var modules = new List<CoverageModuleDto>();
        foreach (var (moduleName, mAcc) in moduleAcc)
        {
            long mTotalSeq = 0, mCoveredSeq = 0, mTotalBr = 0, mCoveredBr = 0;
            var classes = new List<CoverageClassDto>();
            foreach (var cAcc in mAcc.Classes.Values)
            {
                long cTotalSeq = 0, cCoveredSeq = 0, cTotalBr = 0, cCoveredBr = 0;
                foreach (var methAcc in cAcc.Methods.Values)
                {
                    cTotalSeq += methAcc.SeqPoints.Count;
                    cCoveredSeq += methAcc.SeqPoints.Values.Count(v => v);
                    cTotalBr += methAcc.BranchPoints.Count;
                    cCoveredBr += methAcc.BranchPoints.Values.Count(v => v);
                }
                mTotalSeq += cTotalSeq;
                mCoveredSeq += cCoveredSeq;
                mTotalBr += cTotalBr;
                mCoveredBr += cCoveredBr;

                classes.Add(new CoverageClassDto(
                    FullName: cAcc.FullName,
                    SourceFileRelativePath: cAcc.RelativePath,
                    SequenceCoverage: cTotalSeq == 0 ? 0 : 100.0 * cCoveredSeq / cTotalSeq,
                    BranchCoverage: cTotalBr == 0 ? 0 : 100.0 * cCoveredBr / cTotalBr,
                    CoveredSequences: (int)cCoveredSeq,
                    TotalSequences: (int)cTotalSeq,
                    CoveredBranches: (int)cCoveredBr,
                    TotalBranches: (int)cTotalBr,
                    VisitedLines: cAcc.Visited.OrderBy(x => x).ToArray(),
                    UnvisitedLines: cAcc.Unvisited.OrderBy(x => x).ToArray()));
            }

            rootTotalSeq += mTotalSeq;
            rootCoveredSeq += mCoveredSeq;
            rootTotalBr += mTotalBr;
            rootCoveredBr += mCoveredBr;

            modules.Add(new CoverageModuleDto(
                Name: moduleName,
                SequenceCoverage: mTotalSeq == 0 ? 0 : 100.0 * mCoveredSeq / mTotalSeq,
                BranchCoverage: mTotalBr == 0 ? 0 : 100.0 * mCoveredBr / mTotalBr,
                CoveredSequences: (int)mCoveredSeq,
                TotalSequences: (int)mTotalSeq,
                Classes: classes
                    .OrderBy(c => c.FullName, StringComparer.OrdinalIgnoreCase)
                    .ToList()));
        }
        modules = modules.OrderBy(m => m.Name, StringComparer.OrdinalIgnoreCase).ToList();

        // Build unique source-file payload, reading from disk so the dashboard
        // never depends on the build host's filesystem at view time.
        var sourceFiles = new List<CoverageSourceFileDto>();
        var seenPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var mAcc in moduleAcc.Values)
        {
            foreach (var cAcc in mAcc.Classes.Values)
            {
                if (!seenPaths.Add(cAcc.RelativePath)) continue;
                string source = "";
                try { if (File.Exists(cAcc.AbsolutePath)) source = File.ReadAllText(cAcc.AbsolutePath); }
                catch { /* empty source — SPA still renders the line map */ }
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
            SequenceCoverage: rootTotalSeq == 0 ? 0 : 100.0 * rootCoveredSeq / rootTotalSeq,
            BranchCoverage: rootTotalBr == 0 ? 0 : 100.0 * rootCoveredBr / rootTotalBr,
            CoveredSequences: (int)rootCoveredSeq,
            TotalSequences: (int)rootTotalSeq,
            CoveredBranches: (int)rootCoveredBr,
            TotalBranches: (int)rootTotalBr,
            Modules: modules,
            SourceFiles: sourceFiles);
    }

    private static string NormaliseRelativePath(string absolutePath, string repoRoot)
    {
        try
        {
            var rel = Path.GetRelativePath(repoRoot, absolutePath);
            return rel.Replace('\\', '/');
        }
        catch { return absolutePath; }
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

    // Class FullName from OpenCover for nested compiler artifacts looks like
    // "Tamp.Findings.Api.Endpoints.FindingsListEndpoints/<ListFindingsAsync>d__1"
    // (state machine), ".../<>c" (lambda host), ".../<>c__DisplayClass5_0"
    // (closure host). Any '/' indicates nesting; the parent class is everything
    // before the first '/<' (or the whole string if no nested marker is present).
    private static string FoldNestedCompilerArtifact(string className)
    {
        var idx = className.IndexOf("/<", StringComparison.Ordinal);
        return idx >= 0 ? className[..idx] : className;
    }

    private sealed class ModuleAcc
    {
        public Dictionary<string, ClassAcc> Classes { get; } = new(StringComparer.OrdinalIgnoreCase);
    }

    private sealed class ClassAcc
    {
        public string FullName { get; set; } = "";
        public string RelativePath { get; set; } = "";
        public string AbsolutePath { get; set; } = "";
        public Dictionary<string, MethodAcc> Methods { get; } = new();
        public HashSet<int> Visited { get; } = new();
        public HashSet<int> Unvisited { get; } = new();
    }

    private sealed class MethodAcc
    {
        public Dictionary<SpKey, bool> SeqPoints { get; } = new();
        public Dictionary<BpKey, bool> BranchPoints { get; } = new();
    }

    // Source-position identity for a sequence/branch point — stable across
    // multiple Coverlet XMLs of the same assembly.
    private readonly record struct SpKey(int Sl, int Sc, int El, int Ec);
    private readonly record struct BpKey(int Sl, int Sc, int El, int Ec, int Offset, int Order);
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
