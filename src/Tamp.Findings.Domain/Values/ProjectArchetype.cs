namespace Tamp.Findings.Domain.Values;

/// <summary>
/// What kind of thing a project is, for policy composition (TFND-203). The archetype is an
/// ADDITIVE obligation layer over the client's compliance baseline: Library adds nothing,
/// Container adds image obligations, Service adds web + IaC + image obligations. Because it only
/// ever ADDS, no caller input can subtract an obligation — the archetype is downgrade-proof.
///
/// Crucially this is set INSIDE tamp.findings by a human (EditGates), NOT asserted by the
/// ingesting caller: it is the trust boundary. A caller's self-declared
/// <see cref="Tamp.Findings.Domain.Compliance.ComponentProfile"/> can suggest a value and flag a
/// contradiction, but it can never excuse a gate.
///
/// An UNCLASSIFIED project (null) fails UPWARD — it is treated as the strictest archetype
/// (<see cref="ServiceApp"/>), so a project only gets a lighter posture once a human deliberately
/// classifies it down.
/// </summary>
public enum ProjectArchetype
{
    /// <summary>A library / tool / task (source + deps): the client baseline, no web/image/iac
    /// obligations added.</summary>
    Library = 0,

    /// <summary>Shipped as an image but not web-facing (a job, a Docker/GitHub action): the
    /// baseline + base-image freshness.</summary>
    ContainerAction = 1,

    /// <summary>A hosted, web-facing app/service: the baseline + DAST + IaC + base-image. The
    /// strictest archetype, and the fail-upward default for an unclassified project.</summary>
    ServiceApp = 2,
}
