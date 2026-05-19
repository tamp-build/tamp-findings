using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Api.Contracts;

// Wire shape for creating a suppression. Authoring headers
// (X-Author-User, X-Author-Role) are validated separately by the
// endpoint and not part of this body. Scope dictates which of the
// nullable target fields must be set:
//
//   SingleFinding    requires FindingId
//   RuleOnFile       requires RuleId + FilePath
//   RuleOnComponent  requires RuleId + ComponentId
//   RuleEverywhere   requires only RuleId
public sealed record SuppressionCreateRequest(
    SuppressionScope Scope,
    Guid? FindingId,
    string? RuleId,
    Guid? ComponentId,
    string? FilePath,
    string Reason,
    DateTimeOffset? ExpiresAt);

public sealed record SuppressionResponse(
    Guid Id,
    SuppressionScope Scope,
    Guid? FindingId,
    string? RuleId,
    Guid? ComponentId,
    string? FilePath,
    Guid CreatedByUserId,
    string CreatedByUserLogin,
    ProjectRole CreatedByRole,
    string Reason,
    DateTimeOffset? ExpiresAt,
    DateTimeOffset CreatedAt,
    bool IsActive);
