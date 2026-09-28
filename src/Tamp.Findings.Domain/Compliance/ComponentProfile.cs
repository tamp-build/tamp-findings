using Tamp.Findings.Domain.Risk;

namespace Tamp.Findings.Domain.Compliance;

/// <summary>
/// A component's capability profile (TFND-183) — the applicability axis, kept
/// separate from the baseline strictness axis. It declares which conditional
/// scanners a component can even produce, so a gate the baseline requires but
/// the component cannot run resolves to N/A-justified rather than a false block
/// or (worse) a false pass. A library has no runtime, no boundary, no infra — it
/// cannot emit DAST, IaC or base-image findings, and it must be able to say so.
/// </summary>
public enum ComponentProfile
{
    /// <summary>A library / tool / task: source + deps only. The safe default and
    /// the majority (NuGet packages, dotnet tools, MSBuild tasks).</summary>
    CodePackage = 0,
    /// <summary>Shipped as an image but not web-facing (jobs, Docker actions):
    /// + image (base-image age, image scan).</summary>
    Container = 1,
    /// <summary>A hosted, web-facing system: + web (DAST) + iac (IaC misconfig).</summary>
    Service = 2,
}

/// <summary>The capability flags a profile carries. What a component can produce.</summary>
[Flags]
public enum ComponentCapability
{
    None = 0,
    Source = 1,
    Deps = 2,
    Image = 4,
    Web = 8,
    Iac = 16,
}

public static class ComponentProfiles
{
    public static ComponentCapability Capabilities(ComponentProfile p) => p switch
    {
        ComponentProfile.CodePackage => ComponentCapability.Source | ComponentCapability.Deps,
        ComponentProfile.Container => ComponentCapability.Source | ComponentCapability.Deps | ComponentCapability.Image,
        ComponentProfile.Service => ComponentCapability.Source | ComponentCapability.Deps | ComponentCapability.Image | ComponentCapability.Web | ComponentCapability.Iac,
        _ => ComponentCapability.Source | ComponentCapability.Deps,
    };

    public static bool Has(ComponentProfile p, ComponentCapability cap) => (Capabilities(p) & cap) == cap;

    /// <summary>Whether a component with this profile can produce a given scanner
    /// class. The always-on classes (SAST, Secrets, SBOM, Coverage) apply to
    /// every component; Dynamic scan needs a web surface, IaC needs infra.</summary>
    public static bool ScannerApplies(ComponentProfile p, string scannerClass) => scannerClass switch
    {
        PolicyTemplateDefaults.ScannerClasses.DynamicScan => Has(p, ComponentCapability.Web),
        PolicyTemplateDefaults.ScannerClasses.Iac => Has(p, ComponentCapability.Iac),
        _ => true,
    };

    /// <summary>Parse a declared profile string (from ingest) leniently; unknown
    /// or absent → CodePackage (the safe default).</summary>
    public static ComponentProfile Parse(string? s)
    {
        var norm = (s ?? "").Trim().ToLowerInvariant().Replace("-", "").Replace("_", "").Replace(" ", "");
        return norm switch
        {
            "service" or "web" or "webservice" => ComponentProfile.Service,
            "container" or "image" => ComponentProfile.Container,
            _ => ComponentProfile.CodePackage,
        };
    }
}
