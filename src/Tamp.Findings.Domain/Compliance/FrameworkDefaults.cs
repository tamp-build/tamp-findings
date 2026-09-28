using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Domain.Compliance;

/// <summary>
/// The seeded framework rows (v3 §6). Metadata + provenance only — a framework's
/// real control set comes from its OSCAL profile once imported; the counts here
/// are display labels, honest about draft/overlay state ("112 of ~", "+6
/// controls"), not derived truths.
/// </summary>
public static class FrameworkDefaults
{
    private static Framework F(string slug, string name, FrameworkKind kind, string source,
        string version, string controls, string @params, FrameworkStatus status) => new()
    {
        Slug = slug, Name = name, Kind = kind, Source = source, Version = version,
        ControlCountLabel = controls, ParamsLabel = @params, Status = status, IsSeeded = true,
    };

    public static List<Framework> Build() =>
    [
        F("fr-mod", "FedRAMP Rev 5 Moderate", FrameworkKind.Oscal,
            "GSA/fedramp-automation · OSCAL baseline profile", "Rev 5 · 2026-05", "323", "FedRAMP-assigned values", FrameworkStatus.Current),
        F("fr-high", "FedRAMP Rev 5 High", FrameworkKind.Oscal,
            "GSA/fedramp-automation · OSCAL baseline profile", "Rev 5 · 2026-05", "410", "FedRAMP-assigned values", FrameworkStatus.Current),
        F("fr-low", "FedRAMP Rev 5 Low", FrameworkKind.Oscal,
            "GSA/fedramp-automation · OSCAL baseline profile", "Rev 5 · 2026-05", "156", "FedRAMP-assigned values", FrameworkStatus.Current),
        F("nist-low", "NIST SP 800-53B Low", FrameworkKind.Oscal,
            "usnistgov/oscal-content · rev5 baseline profile", "5.2.0", "149", "Organization-defined (SSP)", FrameworkStatus.Current),
        F("nist-mod", "NIST SP 800-53B Moderate", FrameworkKind.Oscal,
            "usnistgov/oscal-content · rev5 baseline profile", "5.2.0", "287", "Organization-defined (SSP)", FrameworkStatus.Current),
        F("gr-core", "GovRAMP Core", FrameworkKind.Curated,
            "Curated from the GovRAMP Core Verification control list", "SAF 4.2", "60", "Organization-defined (SSP)", FrameworkStatus.Current),
        F("gr-mod", "GovRAMP Moderate", FrameworkKind.Curated,
            "Curating from GovRAMP Rev 5 templates", "SAF 4.2", "112 of ~", "Not started", FrameworkStatus.Draft),
        F("mer-ovl", "Meridian Federal overlay", FrameworkKind.Overlay,
            "Tailors FedRAMP Rev 5 Moderate", "v3", "+6 controls", "14 values override FedRAMP", FrameworkStatus.Current),
    ];
}
