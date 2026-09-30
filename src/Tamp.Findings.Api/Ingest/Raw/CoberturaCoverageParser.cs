using System.Globalization;
using System.Xml.Linq;
using Tamp.Findings.Api.Contracts;

namespace Tamp.Findings.Api.Ingest.Raw;

// Cobertura XML (coverlet's `--format cobertura`; also what most non-.NET coverage tools emit). The
// root <coverage> carries line-rate/branch-rate plus, in coverlet's dialect, lines-covered/lines-valid
// counts. Modules are <package> elements; a package's line counts are summed from its classes' <line>
// hits so the numbers hold even when a producer omits the roll-up attributes. Per-class counts and line lists are kept (source text is not)
// — see ParsedCoverage.
public static class CoberturaCoverageParser
{
    public static ParsedCoverage Parse(XDocument doc)
    {
        var root = doc.Root ?? throw new RawReportXml.MalformedException("empty cobertura");

        var modules = new List<CoverageModuleDto>();
        var files = new Dictionary<string, CoverageSourceFileDto>(StringComparer.OrdinalIgnoreCase);
        var sources = (root.Element("sources")?.Elements("source").Select(e => e.Value.Replace('\\', '/').TrimEnd('/')) ?? [])
            .Where(v => v.Length > 0).ToList();
        int allLines = 0, allCovered = 0;
        foreach (var pkg in root.Element("packages")?.Elements("package") ?? [])
        {
            var name = (string?)pkg.Attribute("name") ?? "";
            int total = 0, covered = 0;
            var classes = new List<CoverageClassDto>();
            foreach (var cls in pkg.Element("classes")?.Elements("class") ?? [])
            {
                var visited = new List<int>(); var unvisited = new List<int>();
                int cBranches = 0, tBranches = 0;
                foreach (var line in cls.Element("lines")?.Elements("line") ?? [])
                {
                    total++;
                    var n = Int(line, "number");
                    if (Int(line, "hits") > 0) { covered++; visited.Add(n); } else unvisited.Add(n);
                    var m = ConditionRx.Match((string?)line.Attribute("condition-coverage") ?? "");
                    if (m.Success) { cBranches += int.Parse(m.Groups[1].Value, CultureInfo.InvariantCulture); tBranches += int.Parse(m.Groups[2].Value, CultureInfo.InvariantCulture); }
                }
                var path = RelativePath((string?)cls.Attribute("filename"), sources);
                var cname = (string?)cls.Attribute("name");
                if (path is null || string.IsNullOrWhiteSpace(cname)) continue;
                files.TryAdd(path, new CoverageSourceFileDto(path, null, ""));
                var ct = visited.Count + unvisited.Count;
                classes.Add(new CoverageClassDto(cname, path,
                    ct > 0 ? Pct(visited.Count, ct) : Rate(cls, "line-rate"),
                    tBranches > 0 ? Pct(cBranches, tBranches) : Rate(cls, "branch-rate"),
                    visited.Count, ct, cBranches, tBranches, [.. visited], [.. unvisited]));
            }
            allLines += total;
            allCovered += covered;
            modules.Add(new CoverageModuleDto(
                Name: string.IsNullOrWhiteSpace(name) ? "(default)" : name,
                SequenceCoverage: total > 0 ? Pct(covered, total) : Rate(pkg, "line-rate"),
                BranchCoverage: Rate(pkg, "branch-rate"),
                CoveredSequences: covered,
                TotalSequences: total,
                Classes: classes));   // per-class counts + line lists; no source text on the raw path (stub files)
        }

        // Prefer the root's declared counts when present (coverlet emits them); otherwise fall back to
        // the sum we just computed from the lines.
        var linesValid = Int(root, "lines-valid");
        var linesCovered = Int(root, "lines-covered");
        var totalSeq = linesValid > 0 ? linesValid : allLines;
        var coveredSeq = linesValid > 0 ? linesCovered : allCovered;

        return new ParsedCoverage(
            ToolName: "cobertura",
            SequenceCoverage: totalSeq > 0 ? Pct(coveredSeq, totalSeq) : Rate(root, "line-rate"),
            BranchCoverage: Rate(root, "branch-rate"),
            CoveredSequences: coveredSeq,
            TotalSequences: totalSeq,
            CoveredBranches: Int(root, "branches-covered"),
            TotalBranches: Int(root, "branches-valid"),
            Modules: modules,
            SourceFiles: [.. files.Values]);
    }

    private static readonly System.Text.RegularExpressions.Regex ConditionRx = new(@"\((\d+)/(\d+)\)", System.Text.RegularExpressions.RegexOptions.Compiled);

    // Coverlet writes absolute `filename`s and lists the roots under <sources>; strip the matching root so
    // the same path reads the same across build agents. Falls back to the normalized filename itself.
    private static string? RelativePath(string? filename, List<string> sources)
    {
        if (string.IsNullOrWhiteSpace(filename)) return null;
        var f = filename.Replace('\\', '/');
        foreach (var src in sources)
            if (f.StartsWith(src + "/", StringComparison.OrdinalIgnoreCase)) return f[(src.Length + 1)..];
        return f;
    }

    private static double Pct(int covered, int total) => total > 0 ? Math.Round(100.0 * covered / total, 2) : 0;
    // Cobertura rates are 0..1 fractions; the canonical model is a 0..100 percentage.
    private static double Rate(XElement e, string attr) => double.TryParse((string?)e.Attribute(attr), NumberStyles.Float, CultureInfo.InvariantCulture, out var v) ? Math.Round(v * 100, 2) : 0;
    private static int Int(XElement e, string attr) => int.TryParse((string?)e.Attribute(attr), NumberStyles.Integer, CultureInfo.InvariantCulture, out var v) ? v : 0;
}
