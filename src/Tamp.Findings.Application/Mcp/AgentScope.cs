using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Application.Mcp;

/// <summary>
/// THE scoping rule for the agent surface, in one place (TFND-12, extracted at
/// TFND-251).
///
/// <see cref="AgentReadService"/> owned this privately while reads were the only
/// thing an agent could do. They are not any more — policy editing and hierarchy
/// administration are their own services — and the original reasoning was that a
/// second service reading the same data would need its own check, which would
/// hold only as long as every future author remembered it.
///
/// Copying the rule was the risk, not sharing it. One tested unit that every
/// agent-facing service consults is the structure that reasoning actually asks
/// for; a private method on one of three services was not.
/// </summary>
public sealed class AgentScope
{
    private readonly FindingsDbContext _db;
    private readonly CapabilityEvaluator _capabilities;

    public AgentScope(FindingsDbContext db, CapabilityEvaluator capabilities)
    {
        _db = db;
        _capabilities = capabilities;
    }

    /// <summary>
    /// Why this agent may not read evidence, or null if it may.
    ///
    /// The ordinary capability evaluator at the token's own scope. An agent
    /// holding a role that cannot see evidence is refused for the same reason a
    /// person holding it would be.
    /// </summary>
    public string? DeniedRead(AgentIdentity agent)
    {
        var decision = _capabilities.Evaluate(agent.Principal, Capability.ViewEvidence);
        return decision.Allowed ? null : decision.Reason;
    }

    /// <summary>
    /// Why this agent may not perform <paramref name="capability"/>, or null if
    /// it may.
    ///
    /// Writes ask for the capability the write needs, not for a blanket
    /// "agents may write". An agent token carries a ProjectRole and goes through
    /// the same matrix a person does — the whole point of resolving a token to a
    /// <see cref="Principal"/> rather than to a permission list of its own.
    /// </summary>
    public string? Denied(AgentIdentity agent, Capability capability)
    {
        var decision = _capabilities.Evaluate(agent.Principal, capability);
        return decision.Allowed ? null : decision.Reason;
    }

    /// <summary>
    /// Projects under the token's scope.
    ///
    /// Project-scoped: that project alone, never its siblings.
    /// Client-scoped: every project under that client.
    /// </summary>
    public IQueryable<Project> Visible(AgentIdentity agent)
    {
        var scope = agent.Scope;
        var query = _db.Projects.AsNoTracking();

        if (scope.ProjectId is { } projectId)
            return query.Where(p => p.Id == projectId);

        if (scope.ClientId is { } clientId)
            return query.Where(p => p.ClientId == clientId);

        // No scope is no access, not all access. A token that somehow reached
        // here unscoped reads nothing rather than everything.
        return query.Where(_ => false);
    }

    public async Task<HashSet<Guid>> VisibleIdsAsync(AgentIdentity agent, CancellationToken ct = default) =>
        (await Visible(agent).Select(p => p.Id).ToArrayAsync(ct)).ToHashSet();

    /// <summary>
    /// May this agent act on this project at all?
    ///
    /// The check every tool taking a projectId has to make, because a project id
    /// is a guid an agent could have been handed by anyone and "looks like one of
    /// ours" is not authorization.
    /// </summary>
    public async Task<bool> ReachesAsync(AgentIdentity agent, Guid projectId, CancellationToken ct = default) =>
        (await VisibleIdsAsync(agent, ct)).Contains(projectId);

    /// <summary>
    /// The client a scoped token may create inside, or null when it may not
    /// create at all (TFND-250).
    ///
    /// Creation is the one operation with no existing row to scope against, so
    /// the token's own client is the answer. There is deliberately no
    /// instance-scoped agent token, so there is no case where this means
    /// "anywhere".
    /// </summary>
    public Guid? CreatableClient(AgentIdentity agent) => agent.Scope.ClientId;
}
