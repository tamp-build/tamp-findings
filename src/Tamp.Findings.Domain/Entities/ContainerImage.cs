namespace Tamp.Findings.Domain.Entities;

/// <summary>
/// The container image a build produced, and the base image it was built FROM
/// (TFND-134 / F9.3).
///
/// A base image is usually the single largest source of inherited CVEs in a
/// deployed artefact, and unlike a package it is one line in a Dockerfile — the
/// highest leverage per fix available. Until this existed the product could see
/// every CVE the base image dragged in and could not say where they came from
/// or how old the foundation was.
///
/// Produced by <c>Tamp.Trivy</c>'s <c>InspectImage</c> (TAM-282), which reads
/// the image config without running a scan.
/// </summary>
public sealed class ContainerImage
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public Guid ComponentVersionId { get; set; }

    /// <summary>The image this build produced, e.g. <c>registry.example/app:1.4.2</c>.</summary>
    public required string Reference { get; set; }

    /// <summary>Its digest, when the producer resolved one.</summary>
    public string? Digest { get; set; }

    /// <summary>When this image was built, from its own config.</summary>
    public DateTimeOffset? CreatedAt { get; set; }

    /// <summary>OS family and version Trivy identified, for display.</summary>
    public string? OsFamily { get; set; }
    public string? OsVersion { get; set; }

    public long? SizeBytes { get; set; }

    /// <summary>
    /// The base image reference, when it is KNOWN.
    ///
    /// Null far more often than not, and that absence is load-bearing rather
    /// than an oversight. The OCI annotation that carries it
    /// (<c>org.opencontainers.image.base.name</c>) is set only under some
    /// BuildKit configurations — neither the official .NET images nor Alpine
    /// carry it — so the reliable path is the adopter naming their base image
    /// in the build script. Inferring one from layer history would produce a
    /// confident guess, and this screen would present it as a fact.
    /// </summary>
    public string? BaseImageReference { get; set; }

    public string? BaseImageDigest { get; set; }

    /// <summary>
    /// When the base image tag was published.
    ///
    /// THE field the age score reads. Requires the producer to have inspected
    /// the base reference as well as the built image — two Trivy calls, which
    /// is why it can be null even when <see cref="BaseImageReference"/> is not.
    /// </summary>
    public DateTimeOffset? BaseImageCreatedAt { get; set; }

    /// <summary>When this metadata was captured.</summary>
    public DateTimeOffset InspectedAt { get; set; } = DateTimeOffset.UtcNow;

    public ComponentVersion? ComponentVersion { get; set; }

    /// <summary>
    /// How old the base image was when this build ran, in days.
    ///
    /// Measured against the BUILD, not against today, so the number does not
    /// drift upward every time somebody opens the page. "The base image was 400
    /// days old when we shipped this" is a fact about the release; "it is 400
    /// days old now" is a fact about the calendar.
    /// </summary>
    public int? BaseImageAgeInDays =>
        BaseImageCreatedAt is { } created && InspectedAt > created
            ? (int)(InspectedAt - created).TotalDays
            : BaseImageCreatedAt is null ? null : 0;
}
