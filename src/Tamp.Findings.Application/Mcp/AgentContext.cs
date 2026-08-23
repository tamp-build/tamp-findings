namespace Tamp.Findings.Application.Mcp;

/// <summary>
/// The agent behind the request currently being served (TFND-12).
///
/// Scoped. The transport resolves the presented token exactly once, at the
/// door, and puts the result here; the tools read it. Tools deliberately cannot
/// take a token or a scope as a parameter — if they could, a tool added later
/// would be one forgotten check away from reading another tenant's evidence,
/// and that check would be invisible in the tool's own signature.
/// </summary>
public sealed class AgentContext
{
    private AgentIdentity? _identity;

    /// <summary>Set once, by the transport, after the token resolves.</summary>
    public void Attach(AgentIdentity identity)
    {
        if (_identity is not null)
            throw new InvalidOperationException("The agent identity for this request is already set.");

        _identity = identity;
    }

    public AgentIdentity? Identity => _identity;

    /// <summary>
    /// The identity, or a throw.
    ///
    /// Throwing rather than returning an empty scope: a tool running without an
    /// identity is a wiring defect, and the failure mode of "returns nothing"
    /// is a support ticket about missing findings six weeks later.
    /// </summary>
    public AgentIdentity Require() =>
        _identity ?? throw new InvalidOperationException(
            "No agent identity is attached to this request. The MCP transport must resolve the "
            + "presented token before any tool runs.");
}
