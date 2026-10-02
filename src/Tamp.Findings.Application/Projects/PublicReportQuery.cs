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

        return new PublicReportData(project.Client.Name, project.Name,
            new PublicReportBody(
                ProjectStatus.From(data), data, receipts, coverage, tests, sbom,
                cves.Select(c => new PublicCve(c.AdvisoryId, c.Severity.ToString(), c.Package, c.Version, c.FixedIn)).ToList(),
                cov, board.Stats),
            DateTimeOffset.UtcNow);
    }
}

public sealed record PublicReportData(string Client, string Project, PublicReportBody? Body, DateTimeOffset GeneratedAt);

public sealed record PublicReportBody(
    ProjectStatus Status,
    ProjectHubData Hub,
    IReadOnlyList<PublicReceipt> Receipts,
    CoverageSummary? Coverage,
    TestsSummary? Tests,
    SbomSummary? Sbom,
    IReadOnlyList<PublicCve> Cves,
    ControlCoverage? Controls,
    PoamStats Poam);

public sealed record PublicReceipt(string Scanner, string Status, int FindingsCount, DateTimeOffset? CompletedAt, string? Tool, string? ToolVersion);
public sealed record PublicCve(string AdvisoryId, string Severity, string Package, string Version, string? FixedIn);
