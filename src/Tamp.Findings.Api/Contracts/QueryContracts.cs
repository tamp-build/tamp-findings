using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Api.Contracts;

public sealed record FindingSummary(
    Guid Id,
    ScannerKind Scanner,
    string RuleId,
    Severity Severity,
    string Title,
    string? FilePath,
    int? Line,
    FindingStatus Status,
    DateTimeOffset FirstSeen,
    DateTimeOffset LastSeen);

public sealed record SeverityCounts(
    int Info,
    int Low,
    int Medium,
    int High,
    int Critical)
{
    public int Total => Info + Low + Medium + High + Critical;
}

public sealed record ComponentVersionFindings(
    Guid ComponentVersionId,
    string VersionString,
    SeverityCounts Counts,
    IReadOnlyList<FindingSummary> Findings);
