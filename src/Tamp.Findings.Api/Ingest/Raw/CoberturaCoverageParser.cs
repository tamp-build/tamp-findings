using System.Globalization;
using System.Xml.Linq;
using Tamp.Findings.Api.Contracts;

namespace Tamp.Findings.Api.Ingest.Raw;

// Cobertura XML (coverlet's `--format cobertura`; also what most non-.NET coverage tools emit). The
// root <coverage> carries line-rate/branch-rate plus, in coverlet's dialect, lines-covered/lines-valid
// counts. Modules are <package> elements; a package's line counts are summed from its classes' <line>
// hits so the numbers hold even when a producer omits the roll-up attributes. Line-level overlay is not
// produced on the raw path — see ParsedCoverage.
public static class CoberturaCoverageParser
{
    public static ParsedCoverage Parse(XDocument doc)
    {
        var root = doc.Root ?? throw new RawReportXml.MalformedException("empty cobertura");

        var modules = new List<CoverageModuleDto>();
        int allLines = 0, allCovered = 0;
        foreach (var pkg in root.Element("packages")?.Elements("package") ?? [])
        {
            var name = (string?)pkg.Attribute("name") ?? "";
            int total = 0, covered = 0;
            foreach (var cls in pkg.Element("classes")?.Elements("class") ?? [])
            {
                foreach (var line in cls.Element("lines")?.Elements("line") ?? [])
                {
                    total++;
                    if (Int(line, "hits") > 0) covered++;
                }
            }
            allLines += total;
            allCovered += covered;
            modules.Add(new CoverageModuleDto(
                Name: string.IsNullOrWhiteSpace(name) ? "(default)" : name,
                SequenceCoverage: total > 0 ? Pct(covered, total) : Rate(pkg, "line-rate"),
                BranchCoverage: Rate(pkg, "branch-rate"),
                CoveredSequences: covered,
                TotalSequences: total,
                Classes: null));   // no source text on the raw path → no line-level classes
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
            Modules: modules);
    }

    private static double Pct(int covered, int total) => total > 0 ? Math.Round(100.0 * covered / total, 2) : 0;
    // Cobertura rates are 0..1 fractions; the canonical model is a 0..100 percentage.
    private static double Rate(XElement e, string attr) => double.TryParse((string?)e.Attribute(attr), NumberStyles.Float, CultureInfo.InvariantCulture, out var v) ? Math.Round(v * 100, 2) : 0;
    private static int Int(XElement e, string attr) => int.TryParse((string?)e.Attribute(attr), NumberStyles.Integer, CultureInfo.InvariantCulture, out var v) ? v : 0;
}
