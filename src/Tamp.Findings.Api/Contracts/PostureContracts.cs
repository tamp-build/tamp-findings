namespace Tamp.Findings.Api.Contracts;

// Producer-reported control-posture facts (TFND-212): the observed state of repo/org settings such as
// branch protection or org 2FA. findings owns which checks exist (PostureChecks) and what they gate;
// the producer only states what it observed. Project-scoped: addressed by client + project, no build.
public sealed record PostureIngestRequest(
    string Client,
    string Project,
    IReadOnlyList<PostureObservationDto> Observations,
    string? Source = null);

public sealed record PostureObservationDto(
    string CheckId,                 // a PostureChecks id, e.g. "branch-protection"
    string Status,                  // "pass" | "fail" | "not-applicable" | "unknown"
    string? Detail = null,          // short evidence, e.g. "2 approvals required; force-push blocked"
    DateTimeOffset? ObservedAt = null);

public sealed record PostureIngestResponse(Guid ProjectId, int Accepted, int Created, int Updated);
