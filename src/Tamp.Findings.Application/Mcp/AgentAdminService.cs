using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Application.Projects;
using Tamp.Findings.Data;

namespace Tamp.Findings.Application.Mcp;

/// <summary>
/// Hierarchy administration an agent may perform (TFND-250).
///
/// Separate from <see cref="AgentReadService"/> because that class reads and
/// this one writes, and its own comment says so. Both consult
/// <see cref="AgentScope"/>, which is where the scoping rule lives — shared, not
/// copied.
///
/// Projects only. Two things an agent deliberately cannot create:
///
/// A CLIENT, because <see cref="HierarchyService.CreateClientAsync"/> requires
/// <c>Actor.Admin</c> and an agent principal is built with <c>isAdmin: false</c>
/// unconditionally — so the attempt would be denied anyway. That is the right
/// answer rather than a limitation to work around: a client is a tenant
/// boundary, every scope beneath it inherits from it, and a token scoped to one
/// client creating another would be escalation by a different name.
///
/// A BUILD, because builds arrive through ingest. An agent inventing one would
/// be fabricating a build record, and this product's only asset is that its
/// records are not fabricated.
/// </summary>
public sealed class AgentAdminService
{
    private readonly FindingsDbContext _db;
    private readonly AgentScope _scope;
    private readonly HierarchyService _hierarchy;

    public AgentAdminService(FindingsDbContext db, AgentScope scope, HierarchyService hierarchy)
    {
        _db = db;
        _scope = scope;
        _hierarchy = hierarchy;
    }

    /// <summary>
    /// Create a project inside the token's own client.
    ///
    /// The client is taken from the TOKEN, never from an argument. A client id
    /// parameter would be a parameter an agent could set to somebody else's
    /// client, and the only thing standing between that and another tenant's
    /// tree would be a check this method remembered to make.
    ///
    /// Delegates to <see cref="HierarchyService.CreateProjectAsync"/>, so the
    /// capability check, the name rules and the audit entry are the ones a person
    /// gets. In practice this means only an Architect-roled token can create
    /// anything — <c>CreateProject</c> is held by Admin and Architect, and an
    /// agent is never Admin.
    /// </summary>
    public async Task<AgentAdminResult> CreateProjectAsync(
        AgentIdentity agent, string name, string? description, CancellationToken ct = default)
    {
        if (_scope.CreatableClient(agent) is not { } clientId)
        {
            return AgentAdminResult.Refused(
                "This token is not scoped to a client, so there is nowhere for it to create a "
                + "project. An agent token always carries a client; one that does not is a wiring "
                + "defect worth reporting.");
        }

        if (_scope.Denied(agent, Authorization.Capability.CreateProject) is { } denied)
        {
            return AgentAdminResult.Refused(
                denied + " Creating a project needs the CreateProject capability, which an agent "
                + "token carries only when it was minted as Architect.");
        }

        var result = await _hierarchy.CreateProjectAsync(
            agent.Principal, clientId, name ?? "", description, ct);

        if (!result.Success)
            return AgentAdminResult.Refused(result.Error ?? "The project could not be created.");

        var created = await _db.Projects.AsNoTracking()
            .Where(p => p.Id == result.Value)
            .Select(p => new { p.Id, p.Name, ClientName = p.Client!.Name })
            .SingleAsync(ct);

        return AgentAdminResult.Created(created.Id, created.Name, created.ClientName);
    }
}

/// <summary>
/// What happened, in a shape a tool can turn into a sentence (TFND-250).
///
/// A refusal carries its reason rather than being a null, because "that did not
/// work" is the least useful thing an agent can be told — it will either retry
/// the same call or report a failure it cannot explain.
/// </summary>
public sealed record AgentAdminResult(
    bool Success, Guid? ProjectId, string? Name, string? Client, string? Refusal)
{
    public static AgentAdminResult Created(Guid id, string name, string client) =>
        new(true, id, name, client, null);

    public static AgentAdminResult Refused(string reason) =>
        new(false, null, null, null, reason);
}
