namespace Tamp.Findings.Domain.Entities;

/// <summary>
/// A human-attested license for a package version whose SBOM did not carry a
/// resolvable SPDX expression (TFND-222).
///
/// Keyed by <see cref="Purl"/> and <b>global</b>: a package version's license is
/// a fact about that artifact, not a per-project legal position — so it is
/// resolved once and every project that pulls the same purl inherits it. The
/// ALLOW/DENY position stays project-layered in policy; this only establishes
/// WHAT the license is, never whether it is acceptable.
///
/// This is the human-attestation fallback for licenses a producer cannot
/// resolve automatically (e.g. old-style NuGet <c>.nuspec</c> that declare a
/// <c>licenseUrl</c> rather than an SPDX expression). When the producer learns
/// to resolve them, these rows become redundant but stay valid.
/// </summary>
public sealed class LicenseResolution
{
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>Exact package-url including version, e.g. "pkg:nuget/System.Memory@4.5.5".</summary>
    public required string Purl { get; set; }

    /// <summary>The resolved SPDX id or expression, e.g. "MIT" or "Apache-2.0".</summary>
    public required string Spdx { get; set; }

    /// <summary>Evidence: where the license was confirmed (project URL, nuspec licenseUrl, etc.).</summary>
    public string? Note { get; set; }

    /// <summary>The login of whoever attested it — this is a human judgement on the record.</summary>
    public string? ResolvedBy { get; set; }

    public DateTimeOffset ResolvedAt { get; set; } = DateTimeOffset.UtcNow;
}
