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

    // The three-layer policy (ADR 0007 / TFND-179): this project's own hardening
    // ON TOP of its client and template. Carries the layerable overlay fields
    // that GatesConfig does not (required scanners, denied licences, POA&M
    // deadlines); the project's gates + enforcement mode continue to live in
    // GatesConfig, which the resolver reads as this layer's gate settings.
    // Null → the project adds no hardening of its own.
    public Risk.PolicyLayer? PolicyLayer { get; set; }

    // The project's archetype (TFND-203): the additive obligation layer composed over the
    // client's baseline (Library adds nothing / Container adds image / Service adds web+iac+image).
    // Set INSIDE findings by a human (EditGates) — the trust boundary — never by the ingesting
    // caller. Null = unclassified, which fails UPWARD (resolved as the strictest, Service), so a
    // project only gets a lighter posture once a human deliberately classifies it down.
    public Values.ProjectArchetype? Archetype { get; set; }

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
    // TFND-23: "owner/name" on GitHub, when this project maps to a repository.
    //
    // Per PROJECT rather than derived from the commit, because a commit sha
    // says nothing about which repository it came from — the same sha can exist
    // in a fork, and posting a check run to the wrong repository is a message
    // to someone else's team.
    //
    // Null means "do not publish checks for this project", which is the default
    // and the right one: most projects have no GitHub repository, and guessing
    // one from a name would eventually guess wrong.
    public string? GitHubRepository { get; set; }

    public string? VdpPolicyUrl { get; set; }
    public string? VdpContactEmail { get; set; }
    public string? VdpReportingFormUrl { get; set; }

    public Client? Client { get; set; }
    // Component-collapse PR1: builds anchor directly to the project now. Components stays
    // during the dual-write window and is removed in PR2 along with the Component entity.
    public ICollection<ComponentVersion> Versions { get; set; } = [];
    public ICollection<Component> Components { get; set; } = [];
}
