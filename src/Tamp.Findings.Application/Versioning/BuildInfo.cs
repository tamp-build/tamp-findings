using System.Reflection;

namespace Tamp.Findings.Application.Versioning;

/// <summary>
/// Which build of tamp.findings this process is (TFND-267). Before this, every instance reported OpenAPI
/// <c>info.version</c> "1.0.0" and the only record of the build was the container image tag, which nothing outside
/// the cluster can see — so a customer instance could be ahead of, or behind, the lab with no way to tell.
///
/// The values are stamped into the assembly at build time, so they describe the binary that is running, not
/// whatever an environment variable claims:
/// <list type="bullet">
/// <item><see cref="Version"/> — the product version from <c>Directory.Build.props</c> (<c>&lt;Version&gt;</c>).</item>
/// <item><see cref="Commit"/> — the git commit, which the SDK appends to the informational version as <c>+sha</c>
/// (from SourceLink locally; from the <c>GIT_SHA</c> build argument in the container, where <c>.git</c> is not
/// in the build context).</item>
/// <item><see cref="BuiltAt"/> — the <c>BuildTimestamp</c> assembly metadata, set by the image build.</item>
/// </list>
/// See docs/VERSIONING.md.
/// </summary>
public sealed record BuildInfo(string Version, string? Commit, DateTimeOffset? BuiltAt)
{
    /// <summary>This process's build, read once from the assembly.</summary>
    public static BuildInfo Current { get; } = FromAssembly(typeof(BuildInfo).Assembly);

    /// <summary>The commit abbreviated the way git does (7 characters), or null when unknown.</summary>
    public string? CommitShort => Commit is { Length: >= 7 } c ? c[..7] : Commit;

    /// <summary>The one-line form used in headers, the OpenAPI document and the UI: <c>0.1.0-alpha+5b5bd54</c>.
    /// Without a commit it is just the version, so an unstamped dev build never pretends to be a known one.</summary>
    public string Display => CommitShort is { } c ? $"{Version}+{c}" : Version;

    public static BuildInfo FromAssembly(Assembly assembly)
    {
        var informational = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
            ?? assembly.GetName().Version?.ToString()
            ?? "0.0.0";
        var built = assembly.GetCustomAttributes<AssemblyMetadataAttribute>()
            .FirstOrDefault(a => a.Key == "BuildTimestamp")?.Value;
        return Parse(informational, built);
    }

    /// <summary>Split an informational version (<c>0.1.0-alpha+5b5bd54…</c>) into version and commit, and read an
    /// ISO-8601 build timestamp. Anything after <c>+</c> that is not a hex sha is build metadata, not a commit.</summary>
    public static BuildInfo Parse(string informationalVersion, string? builtAt)
    {
        var plus = informationalVersion.IndexOf('+');
        var version = plus < 0 ? informationalVersion : informationalVersion[..plus];
        var metadata = plus < 0 ? null : informationalVersion[(plus + 1)..];
        var commit = metadata is { Length: >= 7 } m && m.All(Uri.IsHexDigit) ? m.ToLowerInvariant() : null;
        var at = DateTimeOffset.TryParse(builtAt, System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal, out var t)
            ? t : (DateTimeOffset?)null;
        return new BuildInfo(string.IsNullOrWhiteSpace(version) ? "0.0.0" : version, commit, at);
    }
}
