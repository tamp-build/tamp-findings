namespace Tamp.Findings.Domain.Risk;

/// <summary>Normalises package urls to the version-less, lower-cased key the unauthorized-component
/// list is matched on (CM-8(3), TFND-211).</summary>
public static class BannedComponentMatcher
{
    /// <summary><c>pkg:npm/Evil@1.0.0?x=y#z</c> → <c>pkg:npm/evil</c>. Null when it is not a purl.</summary>
    public static string? Key(string? purl)
    {
        if (string.IsNullOrWhiteSpace(purl) || !purl.StartsWith("pkg:", StringComparison.OrdinalIgnoreCase)) return null;
        var end = purl.IndexOfAny(['@', '?', '#'], 4);
        var bare = end < 0 ? purl : purl[..end];
        return Uri.UnescapeDataString(bare).Trim().ToLowerInvariant();
    }

    /// <summary>A banned entry applies when it lists no versions (all banned) or lists this exact version.</summary>
    public static bool VersionMatches(IReadOnlyCollection<string> bannedVersions, string? version) =>
        bannedVersions.Count == 0
        || (version is not null && bannedVersions.Contains(version, StringComparer.OrdinalIgnoreCase));
}
