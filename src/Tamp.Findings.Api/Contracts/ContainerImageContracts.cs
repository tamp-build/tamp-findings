namespace Tamp.Findings.Api.Contracts;

/// <summary>
/// The container image a build produced, and the base image behind it
/// (TFND-134).
///
/// Produced by <c>Tamp.Trivy</c>'s <c>InspectImage</c> + <c>TrivyImageMetadata</c>
/// (TAM-282), which reads an image's config without running a scan.
/// </summary>
public sealed record ContainerImageIngestRequest(
    string Client,
    string Project,
    string Component,
    string? ComponentKind,
    string? Flavor,
    string Version,
    string? CommitSha,
    string? Branch,
    string? BuildId,
    string? PullRequestRef,

    /// <summary>The image this build produced.</summary>
    string Reference,
    string? Digest,
    DateTimeOffset? CreatedAt,
    string? OsFamily,
    string? OsVersion,
    long? SizeBytes,

    /// <summary>
    /// The base image, when the producer could identify it.
    ///
    /// Optional, and expected to be absent often. The OCI annotation that
    /// carries it is set only under some BuildKit configurations, so the
    /// reliable path is the pipeline naming its own base image — one string it
    /// already wrote in its FROM line — and inspecting that too.
    ///
    /// Sending a base reference WITHOUT <see cref="BaseImageCreatedAt"/> is
    /// legitimate and useful: the dashboard can then say which base image is in
    /// play even though it cannot score its age.
    /// </summary>
    string? BaseImageReference = null,
    string? BaseImageDigest = null,
    DateTimeOffset? BaseImageCreatedAt = null);

public sealed record ContainerImageIngestResponse(
    Guid ComponentVersionId,
    Guid ContainerImageId,
    /// <summary>
    /// Null when no base image was supplied or it carried no timestamp. The
    /// caller gets told, rather than having to infer it from a 200.
    /// </summary>
    int? BaseImageAgeInDays,
    string? Note);
