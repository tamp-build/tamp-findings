namespace Tamp.Findings.Domain.Values;

/// <summary>
/// Typed-unified finding routing (TFND-175 expanded). Multi-source quality/SAST
/// tools (SonarQube, SonarAnalyzer/Roslyn, ESLint) tag each finding with an issue
/// TYPE — carried on <c>Finding.SubCategory</c> — and findings routes by that
/// type, not by the tool: a code smell always lands in the quality bucket (so it
/// can never trip <c>criticalSast</c>), and a security issue always lands in SAST,
/// whatever tool found it.
///
/// The type WINS over the scanner's default bucket when present, which is what
/// moves a Roslyn/SonarAnalyzer <c>code_smell</c> out of SAST into quality. The
/// one carve-out is Trivy's <c>vulnerability</c> sub-category (its CVE rows) — those
/// are reconciled as CVEs, not SAST, so security-type routing excludes Trivy.
/// </summary>
public static class FindingTypes
{
    public const string Bug = "bug";
    public const string CodeSmell = "code_smell";
    public const string Vulnerability = "vulnerability";
    public const string SecurityHotspot = "security_hotspot";

    /// <summary>Maintainability/reliability issues — the quality bucket.</summary>
    public static readonly string[] Quality = { Bug, CodeSmell };

    /// <summary>Security issues — the SAST bucket.</summary>
    public static readonly string[] Security = { Vulnerability, SecurityHotspot };

    public static bool IsQualityType(string? sub) => sub == Bug || sub == CodeSmell;
    public static bool IsSecurityType(string? sub) => sub == Vulnerability || sub == SecurityHotspot;
}
