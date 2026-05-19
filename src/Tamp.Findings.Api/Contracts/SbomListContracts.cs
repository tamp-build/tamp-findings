namespace Tamp.Findings.Api.Contracts;

public sealed record SbomComponentListItem(
    Guid Id,
    string Purl,
    string Name,
    string Version,
    string? Kind,
    string Ecosystem,
    string? License,
    int VulnerabilityCount,
    // Denormalized scope for the SPA table
    Guid ComponentVersionId,
    string VersionString,
    Guid ComponentId,
    string ComponentName,
    Guid ProjectId,
    string ProjectName,
    Guid ClientId,
    string ClientName);

public sealed record EcosystemCounts(
    int Nuget,
    int Npm,
    int Other)
{
    public int Total => Nuget + Npm + Other;
}

public sealed record SbomComponentsListResponse(
    int TotalCount,
    int Skip,
    int Take,
    EcosystemCounts Counts,
    int TotalVulnerabilities,
    IReadOnlyList<SbomComponentListItem> Items);

public sealed record VulnerabilityDetail(
    Guid Id,
    string AdvisoryId,
    string Severity,
    string? Title,
    string? Description,
    string? FixedInVersion,
    string? ReferenceUrl,
    string Source);

public sealed record SbomComponentDetail(
    Guid Id,
    string Purl,
    string Name,
    string Version,
    string? Kind,
    string Ecosystem,
    string? License,
    Guid ComponentVersionId,
    string VersionString,
    IReadOnlyList<VulnerabilityDetail> Vulnerabilities,
    IReadOnlyList<string> DependsOnPurls,
    IReadOnlyList<string> DependentPurls);
