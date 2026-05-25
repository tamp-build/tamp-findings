using Tamp;
using Tamp.Findings.Build.Ingest;
using Tamp.Findings.Domain.Values;
using Tamp.Findings.Domain.Entities;
using Tamp.Sarif;

namespace Tamp.Findings.Build.Adapters;

// Builds ScanRunReceiptDto records from scan artifacts already on disk —
// SARIF files, TruffleHog JSONL, etc. The Ingest target accumulates these
// and posts them to /ingest/scan-runs so the dashboard can tell apart
// "scanner ran clean" from "scanner never ran" (TFND-15).
//
// Time-of-scan is approximated from the artifact's last-write timestamp;
// duration we don't track yet (set Started==Completed). That's good enough
// for the dashboard's "did it run" affordance.
public static class ScanRunReceiptBuilder
{
    public static IEnumerable<ScanRunReceiptDto> FromSarif(string sarifPath)
    {
        if (!File.Exists(sarifPath)) yield break;
        SarifLog? log = null;
        ScanRunReceiptDto? failureReceipt = null;
        try { log = SarifReader.LoadFromFile(AbsolutePath.Create(sarifPath)); }
        catch
        {
            failureReceipt = new ScanRunReceiptDto(
                Scanner: ScannerKind.Unknown,
                Status: ScanRunStatus.Failed,
                StartedAt: File.GetLastWriteTimeUtc(sarifPath),
                CompletedAt: File.GetLastWriteTimeUtc(sarifPath),
                FindingsCount: 0,
                ToolName: null,
                ToolVersion: null,
                Notes: $"sarif file at {sarifPath} failed to parse");
        }
        if (failureReceipt is not null) { yield return failureReceipt; yield break; }
        if (log is null) yield break;

        var completed = File.GetLastWriteTimeUtc(sarifPath);

        // A merged SARIF can carry multiple runs (e.g. sast.sarif holds
        // OpenGrep + Roslyn + ReSharper outputs). One receipt per detected
        // scanner; same-scanner runs sum their findings.
        var byScanner = new Dictionary<ScannerKind, (int Count, string? ToolName, string? ToolVersion)>();
        foreach (var run in log.Runs ?? [])
        {
            var driver = run.Tool?.Driver;
            var scanner = InferScanner(driver?.Name);
            if (scanner == ScannerKind.Unknown) continue;
            var count = run.Results?.Count ?? 0;
            if (!byScanner.TryGetValue(scanner, out var cur))
            {
                byScanner[scanner] = (count, driver?.Name, driver?.SemanticVersion ?? driver?.Version);
            }
            else
            {
                byScanner[scanner] = (cur.Count + count, cur.ToolName, cur.ToolVersion);
            }
        }

        foreach (var (scanner, info) in byScanner)
        {
            yield return new ScanRunReceiptDto(
                Scanner: scanner,
                Status: ScanRunStatus.Succeeded,
                StartedAt: completed,
                CompletedAt: completed,
                FindingsCount: info.Count,
                ToolName: info.ToolName,
                ToolVersion: info.ToolVersion,
                Notes: null);
        }
    }

    public static ScanRunReceiptDto? FromTrufflehogJsonl(string jsonlPath)
    {
        if (!File.Exists(jsonlPath)) return null;
        var completed = File.GetLastWriteTimeUtc(jsonlPath);
        // Count non-empty lines as findings — same heuristic the
        // TrufflehogIngestMapper uses to know whether to post anything.
        var count = 0;
        try
        {
            foreach (var line in File.ReadLines(jsonlPath))
                if (!string.IsNullOrWhiteSpace(line)) count++;
        }
        catch
        {
            return new ScanRunReceiptDto(
                Scanner: ScannerKind.TruffleHog,
                Status: ScanRunStatus.Failed,
                StartedAt: completed,
                CompletedAt: completed,
                FindingsCount: 0,
                ToolName: "TruffleHog",
                ToolVersion: null,
                Notes: $"jsonl at {jsonlPath} failed to read");
        }
        return new ScanRunReceiptDto(
            Scanner: ScannerKind.TruffleHog,
            Status: ScanRunStatus.Succeeded,
            StartedAt: completed,
            CompletedAt: completed,
            FindingsCount: count,
            ToolName: "TruffleHog",
            ToolVersion: null,
            Notes: null);
    }

    // Mirrors the scanner-name detection in SarifIngestMapper.InferScanner
    // so receipts and findings agree on which scanner produced which SARIF run.
    private static ScannerKind InferScanner(string? toolDriverName)
    {
        if (string.IsNullOrWhiteSpace(toolDriverName)) return ScannerKind.Unknown;
        var n = toolDriverName.ToLowerInvariant();
        if (n.Contains("opengrep") || n.Contains("semgrep")) return ScannerKind.OpenGrep;
        if (n.Contains("trivy")) return ScannerKind.Trivy;
        if (n.Contains("trufflehog")) return ScannerKind.TruffleHog;
        if (n.Contains("codeql")) return ScannerKind.CodeQL;
        if (n.Contains("osv")) return ScannerKind.OsvScanner;
        if (n.Contains("checkov")) return ScannerKind.Checkov;
        if (n.Contains("inspectcode") || n.Contains("resharper") || n.Contains("jetbrains")) return ScannerKind.ReSharper;
        if (n.Contains("sonar") || n.Contains("roslyn") || n.Contains("roslynator")) return ScannerKind.Roslyn;
        if (n.Contains("c# compiler") || n.Contains("csc") || n.Contains("microsoft (r) visual")) return ScannerKind.Roslyn;
        if (n.Contains("stryker")) return ScannerKind.Stryker;
        if (n.Contains("eslint")) return ScannerKind.ESLint;
        if (n.Contains("axe")) return ScannerKind.AxeCore;
        return ScannerKind.Unknown;
    }
}

// Build-side DTO matching the API contract. Lives alongside the other
// build-side ingest DTOs so the .NET build doesn't drag the Api assembly.
public sealed record ScanRunReceiptDto(
    ScannerKind Scanner,
    ScanRunStatus Status,
    DateTimeOffset StartedAt,
    DateTimeOffset CompletedAt,
    int FindingsCount,
    string? ToolName,
    string? ToolVersion,
    string? Notes);

public sealed record ScanRunIngestRequestDto(
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
    IReadOnlyList<ScanRunReceiptDto> Receipts);
