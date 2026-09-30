using Tamp.Findings.Domain.Compliance;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Domain.Risk;

/// <summary>
/// The archetype obligation layers (TFND-203). Each is a small ADDITIVE <see cref="PolicyLayer"/>
/// composed OVER the client's compliance baseline: it only ever adds gates and required scanners,
/// never removes, so under the strictest-wins merge no caller input can subtract an obligation
/// (the downgrade-proof property). The archetype carries no enforcement mode — it inherits the
/// baseline's — and no denied licences. It DOES carry control-applicability assertions (TFND-209 /
/// ADR 0015): the archetype decides that a Library inherits the runtime control families it never
/// implements while a Service owns them — so the overlay includes which controls it is even on the
/// hook for, not just which extra gates it owes.
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
        ProjectArchetype.Library => Library(),
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

    // A code library implements none of the RUNTIME controls a deployed system does — access control,
    // communications protection, identification/authentication, audit logging. Those are provided by
    // the system that consumes and deploys the library, so they are Inherited, not the library's to
    // evidence. Wireless / mobile-device / collaborative-computing controls do not apply at all.
    //
    // The lists are sourced against FedRAMP High; NIST baselines nest (High ⊇ Moderate ⊇ Low), so this
    // covers every federal library baseline — control ids not in a given baseline are simply ignored by
    // the resolver. Org/authorization common controls (CA/SA/SR/RA/PL program docs) live on the TEMPLATE
    // (they are archetype-independent). The crypto cluster (SC-8/13/28/12/17, IA-7) is dispositioned
    // PER PROJECT, where the code evidence for "we don't ship our own crypto" lives. Controls a library
    // genuinely OWNS (SA-11, RA-5, CM-8, SI-2/7, …) are NOT inherited here — the template gates them.
    // (TFND-209 / ADR 0015. A project override still wins, e.g. a library that really does own a control.)
    private static PolicyLayer Library() => new()
    {
        Assertions =
        {
            new ControlAssertion
            {
                Kind = ControlDispositionKind.Inherited,
                InheritedFrom = "the system that deploys this library (hosting platform + consuming service, under its ATO)",
                Justification = "A code library implements no runtime access control, communications protection, identification/authentication, or audit logging of its own; the deploying system provides them.",
                ControlIds =
                [
                    "AC-2", "AC-2(1)", "AC-2(2)", "AC-2(3)", "AC-2(4)", "AC-2(5)", "AC-2(11)", "AC-2(12)", "AC-2(13)",
                    "AC-3", "AC-4", "AC-4(4)", "AC-5", "AC-6", "AC-6(1)", "AC-6(2)", "AC-6(3)", "AC-6(5)", "AC-6(7)",
                    "AC-6(9)", "AC-6(10)", "AC-7", "AC-8", "AC-10", "AC-11", "AC-11(1)", "AC-12", "AC-14",
                    "AC-17", "AC-17(1)", "AC-17(2)", "AC-17(3)", "AC-17(4)", "AC-20", "AC-20(1)", "AC-20(2)", "AC-21", "AC-22",
                    "AU-2", "AU-3", "AU-3(1)", "AU-4", "AU-5", "AU-5(1)", "AU-5(2)", "AU-6", "AU-6(1)", "AU-6(3)",
                    "AU-6(5)", "AU-6(6)", "AU-7", "AU-7(1)", "AU-8", "AU-9", "AU-9(2)", "AU-9(3)", "AU-9(4)",
                    "AU-10", "AU-11", "AU-12", "AU-12(1)", "AU-12(3)",
                    "IA-2", "IA-2(1)", "IA-2(2)", "IA-2(5)", "IA-2(8)", "IA-2(12)", "IA-3", "IA-4", "IA-4(4)",
                    "IA-5(1)", "IA-5(2)", "IA-5(6)", "IA-6", "IA-8", "IA-8(1)", "IA-8(2)", "IA-8(4)",
                    "IA-11", "IA-12", "IA-12(2)", "IA-12(3)", "IA-12(4)", "IA-12(5)",
                    "SC-2", "SC-3", "SC-4", "SC-5", "SC-7(3)", "SC-7(4)", "SC-7(5)", "SC-7(7)", "SC-7(8)",
                    "SC-7(18)", "SC-7(21)", "SC-10", "SC-20", "SC-21", "SC-22", "SC-23", "SC-24", "SC-39",
                ],
            },
            new ControlAssertion
            {
                Kind = ControlDispositionKind.Inherited,
                InheritedFrom = "the system that deploys this library (hosting platform + consuming service, under its ATO)",
                Justification = "System monitoring, malware protection, memory protection, security alerting, user-facing error handling, and information retention are runtime/operational functions of the deployed system and the organization, not of a code library.",
                ControlIds =
                [
                    "SI-3", "SI-4", "SI-4(2)", "SI-4(4)", "SI-4(5)", "SI-4(10)", "SI-4(12)", "SI-4(20)", "SI-4(22)",
                    "SI-5", "SI-5(1)", "SI-6", "SI-11", "SI-12", "SI-16",
                ],
            },
            new ControlAssertion
            {
                Kind = ControlDispositionKind.Inherited,
                InheritedFrom = "the deployed system, the SCM platform (branch protection / required reviews), and the org change-control program",
                Justification = "Configuration management of a running system — baseline configuration, configuration change control, config settings, least functionality — and the change-control MECHANISM (who may change the code/system) are operational functions of the deployed system, the source-control platform, and the org's change-control program, not of a code library. Fine-grained gated checks (branch-protection verification, change testing) are tracked in TFND-212; component inventory (CM-8) is owned/gated separately.",
                ControlIds =
                [
                    "CM-2(2)", "CM-2(3)", "CM-2(7)", "CM-3", "CM-3(1)", "CM-3(2)", "CM-3(4)", "CM-3(6)",
                    "CM-4", "CM-4(1)", "CM-4(2)", "CM-5", "CM-5(1)", "CM-6(1)", "CM-6(2)",
                    "CM-7(1)", "CM-7(2)", "CM-7(5)", "CM-9", "CM-10", "CM-11", "CM-12", "CM-12(1)",
                ],
            },
            new ControlAssertion
            {
                Kind = ControlDispositionKind.NotApplicable,
                Justification = "The component implements no wireless, mobile-device, collaborative-computing, or messaging/mail technologies, so these controls have no applicable surface.",
                ControlIds =
                [
                    "AC-18", "AC-18(1)", "AC-18(3)", "AC-18(4)", "AC-18(5)", "AC-19", "AC-19(5)", "SC-15",
                    "SI-4(14)", "SI-8", "SI-8(2)",
                ],
            },
        },
    };

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
