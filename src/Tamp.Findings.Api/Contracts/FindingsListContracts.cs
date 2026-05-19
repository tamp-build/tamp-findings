using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Api.Contracts;

public sealed record FindingListItem(
    Guid Id,
    ScannerKind Scanner,
    string RuleId,
    Severity Severity,
    string Title,
    string? FilePath,
    int? Line,
    FindingStatus Status,
    DateTimeOffset FirstSeen,
    DateTimeOffset LastSeen,
    // Denormalized so the table doesn't have to N+1 fetch every parent
    // each row — the Inbox view shows hierarchy inline.
    Guid ComponentVersionId,
    string VersionString,
    Guid ComponentId,
    string ComponentName,
    Guid ProjectId,
    string ProjectName,
    Guid ClientId,
    string ClientName);

public sealed record FindingsListResponse(
    int TotalCount,
    int Skip,
    int Take,
    SeverityCounts Counts,
    IReadOnlyList<FindingListItem> Items);

public sealed record ClientListItem(Guid Id, string Name, int ProjectCount);
public sealed record ProjectListItem(Guid Id, string Name, Guid ClientId, string ClientName, int ComponentCount);
public sealed record ComponentListItem(Guid Id, string Name, string? Kind, Guid ProjectId, string ProjectName, Guid ClientId, string ClientName, int VersionCount);
