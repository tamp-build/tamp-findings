using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Api.Contracts;

// Assign one of the three named roles (InfoSecOfficer / LeadDev /
// Architect) to a user at exactly one tier — Client, Project, or
// Component. The lower tier overrides higher per TFND-3 / F2.2; the
// matcher will walk the hierarchy at read time. POC: any caller can
// create assignments — gating an admin role on creation is a follow-up.
public sealed record RoleAssignmentCreateRequest(
    string UserLogin,
    ProjectRole Role,
    Guid? ClientId,
    Guid? ProjectId,
    Guid? ComponentId);

public sealed record RoleAssignmentResponse(
    Guid Id,
    Guid UserId,
    string UserLogin,
    ProjectRole Role,
    Guid? ClientId,
    string? ClientName,
    Guid? ProjectId,
    string? ProjectName,
    Guid? ComponentId,
    string? ComponentName,
    string Scope,             // "Client" | "Project" | "Component"
    DateTimeOffset CreatedAt);
