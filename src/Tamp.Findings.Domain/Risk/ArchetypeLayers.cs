using Tamp.Findings.Domain.Compliance;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Domain.Risk;

/// <summary>
/// The archetype obligation layers (TFND-203). Each is a small ADDITIVE <see cref="PolicyLayer"/>
/// composed OVER the client's compliance baseline: it only ever adds gates and required scanners,
/// never removes, so under the strictest-wins merge no caller input can subtract an obligation
/// (the downgrade-proof property). The archetype carries no enforcement mode — it inherits the
/// baseline's — and no control assertions or denied licences; it is purely the "what extra does
/// THIS kind of thing owe" overlay.
///
/// Bootstrap-in-code for now; TFND-203 phase B moves these definitions into the distributable
/// content pack so a baseline/archetype change ships as a DB update, not an app republish.
/// </summary>
public static class ArchetypeLayers
{
    /// <summary>The additive obligation layer for an archetype. Library adds nothing.
    /// An unclassified project fails upward to <see cref="ProjectArchetype.ServiceApp"/>.</summary>
    public static PolicyLayer For(ProjectArchetype? archetype) => (archetype ?? ProjectArchetype.ServiceApp) switch
    {
        ProjectArchetype.Library => new(),
        ProjectArchetype.ContainerAction => Container(),
        _ => Service(),
    };

    /// <summary>
    /// The capability that decides which conditional gates BITE for a project of this archetype
    /// (TFND-203). This is the trust fix: gate applicability is driven by the human-assigned
    /// archetype, not the caller-declared <see cref="ComponentProfile"/> — so a web service can't
    /// declare itself a code-package to make its DAST gate go Not-Applicable. Mirrors
    /// <see cref="ComponentProfiles.Capabilities"/> but keyed on the findings-set archetype.
    /// Unclassified fails UPWARD to Service (every capability), so nothing is excused by omission.
    /// </summary>
    public static ComponentCapability Capability(ProjectArchetype? archetype) => (archetype ?? ProjectArchetype.ServiceApp) switch
    {
        ProjectArchetype.Library => ComponentCapability.Source | ComponentCapability.Deps,
        ProjectArchetype.ContainerAction => ComponentCapability.Source | ComponentCapability.Deps | ComponentCapability.Image,
        _ => ComponentCapability.Source | ComponentCapability.Deps | ComponentCapability.Image
            | ComponentCapability.Web | ComponentCapability.Iac,
    };

    /// <summary>A short label for the layer's provenance in the resolved policy.</summary>
    public static string Label(ProjectArchetype? archetype) =>
        $"archetype: {(archetype ?? ProjectArchetype.ServiceApp) switch
        {
            ProjectArchetype.Library => "library",
            ProjectArchetype.ContainerAction => "container/action",
            _ => "service/app",
        }}{(archetype is null ? " (unclassified → fail-upward)" : "")}";

    private static GateConfig On(double? threshold = null) => new() { Enabled = true, Threshold = threshold };

    // + base-image freshness (a container that isn't web-facing).
    private static PolicyLayer Container() => new()
    {
        Gates = { [GateKeys.BaseImageAge] = On(90) },
    };

    // + DAST + IaC required AND gated, + base-image freshness (a hosted web app/service).
    private static PolicyLayer Service() => new()
    {
        RequiredScanners =
        {
            PolicyTemplateDefaults.ScannerClasses.DynamicScan,
            PolicyTemplateDefaults.ScannerClasses.Iac,
        },
        Gates =
        {
            [GateKeys.CriticalDast] = On(0),
            [GateKeys.CriticalIac] = On(0),
            [GateKeys.BaseImageAge] = On(90),
        },
    };
}
