using System.Xml.Linq;
using Tamp.Findings.Build.Ingest;

namespace Tamp.Findings.Build.Adapters;

// Parses every coverage.opencover.xml under artifacts/test-results and
// aggregates into one ingest payload. dotnet test produces one XML per
// test project — modules can overlap (both tests cover the shared
// Domain assembly), so we sum sequence counts per module before
// computing the percentage.
public static class CoverageIngestMapper
{
    public static CoverageIngestRequestDto? Map(string testResultsRoot, IngestBuildContext ctx)
    {
        if (!Directory.Exists(testResultsRoot)) return null;
        var xmls = Directory.EnumerateFiles(testResultsRoot, "coverage.opencover.xml", SearchOption.AllDirectories).ToList();
        if (xmls.Count == 0) return null;

        long totalSeq = 0, coveredSeq = 0, totalBr = 0, coveredBr = 0;
        // module name -> (covered, total) accumulators
        var moduleAcc = new Dictionary<string, (int Covered, int Total)>(StringComparer.OrdinalIgnoreCase);

        foreach (var xmlPath in xmls)
        {
            XDocument doc;
            try { doc = XDocument.Load(xmlPath); }
            catch { continue; }

            var session = doc.Root;
            if (session is null || session.Name.LocalName != "CoverageSession") continue;

            // Root summary — but OpenCover's root <Summary> covers ALL
            // modules including bin/obj noise we want to ignore. Compute
            // totals from the modules we keep instead.
            // Coverlet's OpenCover output puts <Summary> only at the root
            // <CoverageSession> level and inside each <Class>. There is NO
            // <Summary> directly under <Module>. Per-module totals are
            // computed by summing each <Class><Summary> within the module.
            foreach (var module in session.Element("Modules")?.Elements("Module") ?? Enumerable.Empty<XElement>())
            {
                var moduleName = (string?)module.Element("ModuleName");
                if (string.IsNullOrWhiteSpace(moduleName)) continue;
                if (IsTestOrTransient(moduleName)) continue;

                long mTotal = 0, mCovered = 0, mTotalBr = 0, mCoveredBr = 0;
                foreach (var cls in module.Element("Classes")?.Elements("Class") ?? Enumerable.Empty<XElement>())
                {
                    var classSum = cls.Element("Summary");
                    if (classSum is null) continue;
                    var (ct, cc) = ReadSeq(classSum);
                    var (cTb, cCb) = ReadBr(classSum);
                    mTotal += ct; mCovered += cc;
                    mTotalBr += cTb; mCoveredBr += cCb;
                }

                totalSeq += mTotal;
                coveredSeq += mCovered;
                totalBr += mTotalBr;
                coveredBr += mCoveredBr;

                if (moduleAcc.TryGetValue(moduleName, out var cur))
                {
                    moduleAcc[moduleName] = (cur.Covered + (int)mCovered, cur.Total + (int)mTotal);
                }
                else
                {
                    moduleAcc[moduleName] = ((int)mCovered, (int)mTotal);
                }
            }
        }

        if (totalSeq == 0 && moduleAcc.Count == 0) return null;

        var modules = moduleAcc
            .Select(kv => new CoverageModuleDto(
                Name: kv.Key,
                SequenceCoverage: kv.Value.Total == 0 ? 0 : 100.0 * kv.Value.Covered / kv.Value.Total,
                BranchCoverage: 0,  // per-module branch %: cheap to add later, opencover has it
                CoveredSequences: kv.Value.Covered,
                TotalSequences: kv.Value.Total))
            .OrderBy(m => m.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();

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
            BranchCoverage: totalBr == 0 ? 0 : 100.0 * coveredBr / totBr_or(totalBr),
            CoveredSequences: (int)coveredSeq,
            TotalSequences: (int)totalSeq,
            CoveredBranches: (int)coveredBr,
            TotalBranches: (int)totalBr,
            Modules: modules);
    }

    private static double totBr_or(long totalBr) => totalBr;

    private static bool IsTestOrTransient(string moduleName)
    {
        // Tamp's testing convention is *.Tests.* — exclude. Also dodge
        // moq's proxy assemblies and the test-host shim.
        if (moduleName.EndsWith(".Tests", StringComparison.OrdinalIgnoreCase)) return true;
        if (moduleName.Contains(".Tests.", StringComparison.OrdinalIgnoreCase)) return true;
        if (moduleName.StartsWith("xunit.", StringComparison.OrdinalIgnoreCase)) return true;
        if (moduleName.StartsWith("Moq", StringComparison.OrdinalIgnoreCase)) return true;
        if (moduleName.StartsWith("Microsoft.TestPlatform.", StringComparison.OrdinalIgnoreCase)) return true;
        if (moduleName.StartsWith("testhost", StringComparison.OrdinalIgnoreCase)) return true;
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
    IReadOnlyList<CoverageModuleDto> Modules);

public sealed record CoverageModuleDto(
    string Name,
    double SequenceCoverage,
    double BranchCoverage,
    int CoveredSequences,
    int TotalSequences);
