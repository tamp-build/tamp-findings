namespace Tamp.Findings.Application.Authorization;

/// <summary>
/// Decides whether a principal holds a capability.
///
/// This is the single enforcement point named by ADR 0002. The HTTP API, the
/// Blazor UI and the MCP tools all ask this same object, so a transport that
/// forgets to check is not a vulnerability — the layer beneath it refuses.
///
/// Roles are ADDITIVE: effective access is the union across every role the
/// principal holds at the target scope. A user who is both Lead Dev and
/// Architect gets both sets, which is exactly what a three-person team needs.
/// </summary>
public sealed class CapabilityEvaluator
{
    /// <summary>
    /// Evaluate against a resolved principal. Scope resolution — walking the
    /// Client > Project > Component tree and applying narrowest-grant-wins —
    /// is TFND-70, and produces the <see cref="Principal"/> handed in here.
    /// </summary>
    public AuthorizationDecision Evaluate(Principal principal, Capability capability)
    {
        ArgumentNullException.ThrowIfNull(principal);

        // Unconditional grant from any held role wins outright.
        foreach (var actor in principal.Actors)
        {
            if (CapabilityMatrix.Grants_(actor, capability)) return AuthorizationDecision.Allow();
        }

        // Otherwise a conditional grant may apply. Reported as allowed-with-a
        // -condition rather than silently denied, because the caller is the
        // only thing that can evaluate the condition — whether the VEX
        // statement is a draft, whether the target scope is at or below the
        // grantor's own.
        foreach (var actor in principal.Actors)
        {
            var condition = CapabilityMatrix.ConditionFor(actor, capability);
            if (condition is not null) return AuthorizationDecision.AllowIf(condition);
        }

        return AuthorizationDecision.Deny(DenialReason(principal, capability));
    }

    public bool Allows(Principal principal, Capability capability) => Evaluate(principal, capability).Allowed;

    /// <summary>
    /// Everything the principal may do here. Drives the RBAC screen's
    /// "Effective" column (TFND-110), which must be the union the evaluator
    /// actually computes rather than a second implementation of the union.
    /// </summary>
    public IReadOnlySet<Capability> EffectiveCapabilities(Principal principal)
    {
        ArgumentNullException.ThrowIfNull(principal);

        var set = new HashSet<Capability>();
        foreach (var capability in CapabilityMatrix.AllCapabilities)
        {
            if (Evaluate(principal, capability).Allowed) set.Add(capability);
        }
        return set;
    }

    // Denials are read by humans — a disabled button's tooltip and an audit
    // entry — so they name the capability and who could grant it rather than
    // saying "forbidden".
    private static string DenialReason(Principal principal, Capability capability)
    {
        var holders = CapabilityMatrix.AllActors
            .Where(a => CapabilityMatrix.Grants_(a, capability) || CapabilityMatrix.IsConditional(a, capability))
            .ToArray();

        var held = principal.Actors.Count == 0
            ? "no role"
            : string.Join(" + ", principal.Actors);

        return holders.Length == 0
            ? $"{capability} is granted to no role."
            : $"{capability} requires {string.Join(" or ", holders)}; this user holds {held}.";
    }
}
