using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Domain.Entities;

public sealed class Client
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public required string Name { get; set; }
    public string? Description { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    // Null → fall back to the system default policy. Set → applies to
    // every project under this client unless the project overrides.
    public Guid? RiskPolicyId { get; set; }

    // Null → inherit the instance enforcement mode. Set → applies to every
    // project under this client unless the project overrides (TFND-148).
    public EnforcementMode? EnforcementMode { get; set; }

    // The three-layer policy (ADR 0007 / TFND-179). The template this client
    // inherits its baseline from (null → none yet), and the client's own
    // hardening ON TOP of it. The client can only add or tighten; switching the
    // template needs InfoSec approval.
    public Guid? PolicyTemplateId { get; set; }
    public Risk.PolicyLayer? PolicyLayer { get; set; }

    public ICollection<Project> Projects { get; set; } = [];
}
