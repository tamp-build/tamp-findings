using Tamp.Findings.Application.Versioning;

namespace Tamp.Findings.Api.Contracts;

/// <summary>GET /version (TFND-267): which build of tamp.findings answered. See docs/VERSIONING.md.</summary>
/// <param name="Service">Always "tamp.findings.api" (unchanged from the earlier /version, which callers may key on).</param>
/// <param name="Version">Product version from Directory.Build.props, e.g. "0.1.0-alpha".</param>
/// <param name="Commit">Full git commit the binary was built from; null for an unstamped build.</param>
/// <param name="CommitShort">The commit abbreviated to 7 characters.</param>
/// <param name="BuiltAt">When the image was built (UTC); null for an unstamped build.</param>
/// <param name="Display">The one-line form, e.g. "0.1.0-alpha+5b5bd54" — the same value as the
/// X-Tamp-Findings-Version header and the OpenAPI info.version. Quote this in reports.</param>
/// <param name="Runtime">The .NET runtime version.</param>
/// <param name="Source">Link to the commit in the public repository, when the commit is known.</param>
public sealed record VersionResponse(
    string Service,
    string Version,
    string? Commit,
    string? CommitShort,
    DateTimeOffset? BuiltAt,
    string Display,
    string Runtime,
    string? Source)
{
    public static VersionResponse From(BuildInfo build) => new(
        Service: "tamp.findings.api",
        Version: build.Version,
        Commit: build.Commit,
        CommitShort: build.CommitShort,
        BuiltAt: build.BuiltAt,
        Display: build.Display,
        Runtime: $".NET {Environment.Version}",
        Source: build.Commit is { } c ? $"https://github.com/tamp-build/tamp-findings/commit/{c}" : null);

    public static VersionResponse Current() => From(BuildInfo.Current);
}
