namespace Tamp.Findings.Domain.Entities;

public sealed class Project
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid ClientId { get; set; }
    public required string Name { get; set; }
    public string? Description { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    // Null → inherit from this project's client (which in turn falls back
    // to the system default if also null).
    public Guid? RiskPolicyId { get; set; }
    // Per-project acceptance gates (pass/fail blockers). Null → no gates
    // configured (every build passes the gate check). Distinct from
    // RiskPolicy which drives the score.
    public Risk.ProjectGatesConfig? GatesConfig { get; set; }

    // TFND-32: vulnerability disclosure policy metadata. Federal
    // procurement (per CISA BOD 20-01 / NIST SSDF RV.3.1) expects a
    // published path for coordinated disclosure. When any of these are
    // set, the SSDF attestation flips RV.3.1 from Manual → Yes/Partial.
    //
    // Stored as three strings rather than a jsonb POCO because the
    // surface is small + stable and free-text editors are simpler:
    //   - VdpPolicyUrl: public URL of the project's VDP page
    //   - VdpContactEmail: security@... or equivalent inbox
    //   - VdpReportingFormUrl: optional triage form / hackerone /
    //     bugcrowd link
    public string? VdpPolicyUrl { get; set; }
    public string? VdpContactEmail { get; set; }
    public string? VdpReportingFormUrl { get; set; }

    public Client? Client { get; set; }
    public ICollection<Component> Components { get; set; } = [];
}
