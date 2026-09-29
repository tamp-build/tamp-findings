namespace Tamp.Findings.Application.Authorization;

/// <summary>
/// The thing being acted on, expressed as its position in the
/// Client &gt; Project hierarchy.
///
/// Callers pass the full chain rather than a leaf id because the resolver has
/// to know the ancestors to walk inheritance, and looking them up here would
/// mean a database round trip inside an authorization check.
/// </summary>
public readonly record struct ScopeTarget(Guid? ClientId, Guid? ProjectId)
{
    public static ScopeTarget Client(Guid clientId) => new(clientId, null);

    public static ScopeTarget Project(Guid clientId, Guid projectId) => new(clientId, projectId);

    /// <summary>
    /// Instance-level, outside any client or project — the System panels.
    /// Only the Admin flag can grant anything here, since every
    /// ProjectRoleAssignment is scoped to at least a client.
    /// </summary>
    public static ScopeTarget Instance => new(null, null);

    /// <summary>How specific this target is. Higher is narrower.</summary>
    public int Depth => ProjectId is not null ? 2 : ClientId is not null ? 1 : 0;
}
