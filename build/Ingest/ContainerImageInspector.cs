using System.Globalization;
using System.Text.Json;

namespace Tamp.Findings.Build.Ingest;

/// <summary>
/// Reads container image metadata out of a Trivy JSON report (TFND-134).
///
/// This mirrors <c>Tamp.Trivy.TrivyImageMetadata.Parse</c> (TAM-282) and should
/// be DELETED in favour of it the moment Tamp.Trivy 1.11.2 ships — the wrapper
/// is where this belongs, and two copies of a parser eventually disagree about
/// the null cases. It is duplicated here only because the build cannot
/// reference an unreleased package, and shipping the feature unused while
/// waiting for a release would leave it unexercised.
/// </summary>
internal static class ContainerImageInspector
{
    /// <summary>
    /// The exact argv <c>Tamp.Trivy.InspectImage</c> builds.
    ///
    /// <paramref name="remoteOnly"/> matters more than it looks. Trivy's source
    /// order is <c>docker,containerd,podman,remote</c>, so a tag the local
    /// daemon has cached is answered from that cache — the date the cache was
    /// filled, not the date the tag points at now. Measured on this machine:
    /// <c>aspnet:10.0-alpine</c> read 2026-05-12 from the daemon and
    /// 2026-08-10 from the registry. Ninety days, in the direction of making a
    /// current base image look neglected.
    ///
    /// So: ON for a base image looked up by tag, OFF for an image just built
    /// locally and not yet pushed.
    /// </summary>
    public static string[] InspectArgs(string reference, string outputFile, bool remoteOnly)
    {
        var args = new List<string>
        {
            "image", "--format", "json", "--scanners", "",
            "--output", outputFile, "--quiet", "--skip-version-check",
        };

        if (remoteOnly)
        {
            args.Add("--image-src");
            args.Add("remote");
        }

        args.Add(reference);
        return [.. args];
    }

    public static ImageFacts Parse(string json)
    {
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;

        if (!root.TryGetProperty("Metadata", out var meta) || meta.ValueKind != JsonValueKind.Object)
            return new ImageFacts(Text(root, "ArtifactName"), null, null, null, null, null);

        JsonElement? config = meta.TryGetProperty("ImageConfig", out var c)
                              && c.ValueKind == JsonValueKind.Object ? c : null;

        JsonElement? os = meta.TryGetProperty("OS", out var o)
                          && o.ValueKind == JsonValueKind.Object ? o : null;

        return new ImageFacts(
            Text(meta, "Reference") ?? Text(root, "ArtifactName"),
            FirstOf(meta, "RepoDigests"),
            config is { } cfg ? Timestamp(cfg, "created") : null,
            os is { } osv ? Text(osv, "Family") : null,
            os is { } osv2 ? Text(osv2, "Name") : null,
            meta.TryGetProperty("Size", out var size) && size.ValueKind == JsonValueKind.Number
            && size.TryGetInt64(out var bytes) ? bytes : null);
    }

    /// <summary>
    /// The base image of the FINAL stage of a Dockerfile.
    ///
    /// The final stage is what ships — an earlier <c>FROM sdk:…</c> in a
    /// multi-stage build is a compiler that never leaves the build host, and
    /// scoring its age would report a number about something nobody deploys.
    ///
    /// Resolves stage aliases: a final <c>FROM builder</c> walks back to
    /// whatever <c>builder</c> was itself built from. Returns null rather than
    /// guessing when the Dockerfile is shaped in a way this cannot read —
    /// TFND-134 reports "base not identified" for that, which is honest, where
    /// a wrong reference would be scored as fact.
    /// </summary>
    public static string? BaseImageOf(string dockerfile)
    {
        var stages = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        string? last = null;

        foreach (var raw in dockerfile.Split('\n'))
        {
            var line = raw.Trim();
            if (!line.StartsWith("FROM ", StringComparison.OrdinalIgnoreCase)) continue;

            var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2) continue;

            var image = parts[1];

            // "FROM x AS y" — remember the alias so a later "FROM y" resolves.
            var asIndex = Array.FindIndex(parts, p => p.Equals("AS", StringComparison.OrdinalIgnoreCase));
            if (asIndex > 0 && asIndex + 1 < parts.Length) stages[parts[asIndex + 1]] = image;

            last = image;
        }

        if (last is null) return null;

        // Walk aliases back to a real reference, with a bound: a Dockerfile
        // cannot legally contain a FROM cycle, but this runs against files
        // nobody validated and a loop here would hang a build.
        for (var hops = 0; hops < 16 && stages.TryGetValue(last, out var underlying); hops++)
        {
            if (string.Equals(underlying, last, StringComparison.OrdinalIgnoreCase)) break;
            last = underlying;
        }

        // A build ARG in the reference means the real value lives outside the
        // file. Refusing beats resolving it to the literal "${BASE}".
        return last.Contains('$') ? null : last;
    }

    private static string? Text(JsonElement parent, string name) =>
        parent.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    private static string? FirstOf(JsonElement parent, string name)
    {
        if (!parent.TryGetProperty(name, out var array) || array.ValueKind != JsonValueKind.Array) return null;

        foreach (var item in array.EnumerateArray())
            if (item.ValueKind == JsonValueKind.String) return item.GetString();

        return null;
    }

    private static DateTimeOffset? Timestamp(JsonElement parent, string name)
    {
        var raw = Text(parent, name);
        if (string.IsNullOrWhiteSpace(raw)) return null;

        return DateTimeOffset.TryParse(
            raw, CultureInfo.InvariantCulture,
            DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var parsed)
            ? parsed
            : null;
    }
}

internal sealed record ImageFacts(
    string? Reference,
    string? Digest,
    DateTimeOffset? Created,
    string? OsFamily,
    string? OsVersion,
    long? SizeBytes);

/// <summary>Mirrors <c>ContainerImageIngestRequest</c> on the API side.</summary>
internal sealed record ContainerImageIngestRequestDto(
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
    string Reference,
    string? Digest,
    DateTimeOffset? CreatedAt,
    string? OsFamily,
    string? OsVersion,
    long? SizeBytes,
    string? BaseImageReference,
    string? BaseImageDigest,
    DateTimeOffset? BaseImageCreatedAt);
