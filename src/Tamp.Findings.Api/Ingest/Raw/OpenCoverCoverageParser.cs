using System.Globalization;
using System.Xml.Linq;
using Tamp.Findings.Api.Contracts;

namespace Tamp.Findings.Api.Ingest.Raw;

// OpenCover XML (coverlet's `--format opencover`, the default for `dotnet test` coverage). The overall
// numbers live on a <Summary> directly under <CoverageSession>; coverlet emits no per-<Module> summary,
// so a module's coverage is rolled up from its classes' summaries. Line-level overlay is not produced
// on the raw path — see ParsedCoverage.
public static class OpenCoverCoverageParser
{
    public static ParsedCoverage Parse(XDocument doc)
    {
        var root = doc.Root ?? throw new RawReportXml.MalformedException("empty opencover");
        var overall = root.Element("Summary");

        var modules = new List<CoverageModuleDto>();
        foreach (var m in root.Element("Modules")?.Elements("Module") ?? [])
        {
            var name = (string?)m.Element("ModuleName") ?? (string?)m.Element("ModulePath") ?? "";
            if (string.IsNullOrWhiteSpace(name)) continue;

            int seqTotal = 0, seqCovered = 0, brTotal = 0, brCovered = 0;
            foreach (var s in m.Element("Classes")?.Elements("Class").Select(c => c.Element("Summary")) ?? [])
            {
                if (s is null) continue;
                seqTotal += Int(s, "numSequencePoints");
                seqCovered += Int(s, "visitedSequencePoints");
                brTotal += Int(s, "numBranchPoints");
                brCovered += Int(s, "visitedBranchPoints");
            }

            modules.Add(new CoverageModuleDto(
                Name: name,
                SequenceCoverage: Pct(seqCovered, seqTotal),
                BranchCoverage: Pct(brCovered, brTotal),
                CoveredSequences: seqCovered,
                TotalSequences: seqTotal,
                Classes: null));   // no source text on the raw path → no line-level classes
        }

        return new ParsedCoverage(
            ToolName: "opencover",
            SequenceCoverage: overall is not null ? Dbl(overall, "sequenceCoverage") : Pct(modules.Sum(m => m.CoveredSequences), modules.Sum(m => m.TotalSequences)),
            BranchCoverage: overall is not null ? Dbl(overall, "branchCoverage") : 0,
            CoveredSequences: overall is not null ? Int(overall, "visitedSequencePoints") : modules.Sum(m => m.CoveredSequences),
            TotalSequences: overall is not null ? Int(overall, "numSequencePoints") : modules.Sum(m => m.TotalSequences),
            CoveredBranches: overall is not null ? Int(overall, "visitedBranchPoints") : 0,
            TotalBranches: overall is not null ? Int(overall, "numBranchPoints") : 0,
            Modules: modules);
    }

    private static double Pct(int covered, int total) => total > 0 ? Math.Round(100.0 * covered / total, 2) : 0;
    private static int Int(XElement e, string attr) => int.TryParse((string?)e.Attribute(attr), NumberStyles.Integer, CultureInfo.InvariantCulture, out var v) ? v : 0;
    private static double Dbl(XElement e, string attr) => double.TryParse((string?)e.Attribute(attr), NumberStyles.Float, CultureInfo.InvariantCulture, out var v) ? v : 0;
}
