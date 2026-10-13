using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Application.Compliance;
using Tamp.Findings.Application.Poam;
using Tamp.Findings.Application.Risk;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Compliance;
using Tamp.Findings.Domain.Risk;

namespace Tamp.Findings.Application.Projects;

/// <summary>
/// The data behind the PUBLIC evidence report (TFND-215). Anonymous, so it is an explicit allow-list of
/// POSTURE AND COUNTS: no file paths, code snippets, finding titles or descriptions, scan-receipt notes,
/// POA&amp;M text, or control-disposition justifications. CVE rows carry the advisory id, package, version
/// and fixed-in — public information about third-party components, and what a consumer needs to verify.
/// The key in the URL is the authorization, and it only works while the project's toggle is on.
///
/// The allow-list is enforced by the SHAPE of what this returns, not by what the page happens to render.
/// Every record below is scalars and already-narrowed rows, so there is nothing sensitive in the model to
/// leak by accident. That is deliberate: this used to hand the page the whole ProjectHubData and the full
/// ControlCoverage, and the guarantee above held only because no markup had reached for
/// ControlDispositionResult.Detail (justification text, which by ADR 0015 convention cites source files),
/// CoverageSummary.Modules (which bottoms out in file paths), or ContainerImageRow.Reference (a private
/// registry's hostname). One well-meaning @foreach was all it would have taken.
///
/// The one field whose bytes nobody here chose is a posture gate's observed text, which is the producer's
/// own Detail string. It is withheld rather than echoed — see PublicGateText. The verdict is still
/// published; withholding the gate itself would hide the evidence this page exists to show. The
/// public badge shares that rule through ProjectStatus.ForPublic.
/// </summary>
public sealed class PublicReportQuery(
    FindingsDbContext db, ProjectHubQuery hub, CategoryFindingsQuery category,
    ControlDispositionQuery controls, PoamQuery poam)
{
    public async Task<PublicReportData?> LoadAsync(string key, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(key)) return null;
        var project = await db.Projects.AsNoTracking().Include(p => p.Client)
            .FirstOrDefaultAsync(p => p.ReportKey == key && p.PublicReportEnabled, ct);
        if (project?.Client is null) return null;

        var pref = new ProjectRef(project.ClientId, project.Client.Name, project.Id, project.Name,
            project.RiskPolicyId, project.GatesConfig);
        var data = await hub.LoadAsync(pref, commitSha: null, ct);
        if (data is null) return new PublicReportData(project.Client.Name, project.Name, null, DateTimeOffset.UtcNow);

        var sha = data.CommitSha;
        var receipts = (await category.ReceiptsAsync(project.Id, sha, ct))
            .Select(r => new PublicReceipt(r.Scanner.ToString(), r.Status, r.FindingsCount, r.CompletedAt, r.ToolName, r.ToolVersion))
            .ToList();
        var coverage = await category.CoverageAsync(project.Id, sha, ct);
        var tests = await category.TestsAsync(project.Id, sha, ct);
        var sbom = await category.SbomSummaryAsync(project.Id, sha, ct);
        var cves = await category.CvesAsync(project.Id, sha, ct);
        var cov = await controls.ForProjectAsync(project.Id, null, ct);
        var board = await poam.BoardAsync(project.Id, DateTimeOffset.UtcNow, ct);

        // Gate rows, with producer-supplied observed text replaced by a neutral phrase.
        var gates = data.Gates.Results.Where(r => r.Enabled)
            .Select(g => new PublicGate(
                GateEvaluator.Label(g.Key),
                g.Verdict.ToString(),
                PublicGateText.Observed(g),
                g.Blocks))
            .ToList();

        return new PublicReportData(project.Client.Name, project.Name,
            new PublicReportBody(
                ProjectStatus.ForPublic(data),
                data.PolicyName,
                new PublicGates(
                    data.Gates.Passed, data.Gates.Failed, data.Gates.Unknown, data.Gates.NotApplicable, gates),
                receipts,
                coverage is null ? null : new PublicCoverage(
                    coverage.SequencePercent, coverage.CoveredSequences, coverage.TotalSequences,
                    coverage.BranchPercent, coverage.CoveredBranches, coverage.TotalBranches),
                tests is null ? null : new PublicTests(tests.Total, tests.Passed, tests.Failed, tests.Skipped),
                sbom,
                cves.Select(c => new PublicCve(c.AdvisoryId, c.Severity.ToString(), c.Package, c.Version, c.FixedIn)).ToList(),
                cov is null ? null : new PublicControlCounts(
                    cov.InScope, cov.Gated, cov.Inherited, cov.NotApplicable, cov.Unmapped),
                board.Stats),
            DateTimeOffset.UtcNow);
    }
}

public sealed record PublicReportData(string Client, string Project, PublicReportBody? Body, DateTimeOffset GeneratedAt);

public sealed record PublicReportBody(
    ProjectStatus Status,
    string PolicyName,
    PublicGates Gates,
    IReadOnlyList<PublicReceipt> Receipts,
    PublicCoverage? Coverage,
    PublicTests? Tests,
    // Scalars plus the generating tool's name — safe as it stands, and the tool IS evidence.
    SbomSummary? Sbom,
    IReadOnlyList<PublicCve> Cves,
    PublicControlCounts? Controls,
    // All counts.
    PoamStats Poam);

public sealed record PublicReceipt(string Scanner, string Status, int FindingsCount, DateTimeOffset? CompletedAt, string? Tool, string? ToolVersion);
public sealed record PublicCve(string AdvisoryId, string Severity, string Package, string Version, string? FixedIn);
public sealed record PublicGate(string Label, string Verdict, string Observed, bool Blocks);
public sealed record PublicGates(int Passed, int Failed, int Unknown, int NotApplicable, IReadOnlyList<PublicGate> Results);

/// <summary>Coverage totals WITHOUT the module/namespace/file tree, which names source files.</summary>
public sealed record PublicCoverage(
    double SequencePercent, int CoveredSequences, int TotalSequences,
    double BranchPercent, int CoveredBranches, int TotalBranches);

/// <summary>Test totals WITHOUT suite, assembly or failure rows.</summary>
public sealed record PublicTests(int Total, int Passed, int Failed, int Skipped);

/// <summary>Disposition counts WITHOUT the per-control justification text or its policy layer.</summary>
public sealed record PublicControlCounts(int InScope, int Gated, int Inherited, int NotApplicable, int Unmapped);
