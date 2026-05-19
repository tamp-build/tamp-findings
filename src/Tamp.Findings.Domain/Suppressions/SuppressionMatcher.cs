using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Domain.Suppressions;

// Pure-domain decision helper: does any active suppression in `pool` cover
// the given finding? Used by the ingest path to set Status=Suppressed
// during upsert. Kept out of the Data project so the rule stays
// reviewable without spelunking through EF.
public static class SuppressionMatcher
{
    public static bool Covers(
        Suppression s,
        Guid componentId,
        string ruleId,
        string? filePath,
        Guid? existingFindingId,
        DateTimeOffset now)
    {
        // Active = no expiry or expiry still in the future.
        if (s.ExpiresAt is { } exp && exp <= now) return false;

        return s.Scope switch
        {
            SuppressionScope.SingleFinding =>
                existingFindingId is { } id && s.FindingId == id,

            SuppressionScope.RuleOnFile =>
                string.Equals(s.RuleId, ruleId, StringComparison.Ordinal)
                && PathsMatch(s.FilePath, filePath),

            SuppressionScope.RuleOnComponent =>
                string.Equals(s.RuleId, ruleId, StringComparison.Ordinal)
                && s.ComponentId == componentId,

            SuppressionScope.RuleEverywhere =>
                string.Equals(s.RuleId, ruleId, StringComparison.Ordinal),

            _ => false,
        };
    }

    public static bool AnyCovers(
        IEnumerable<Suppression> pool,
        Guid componentId,
        string ruleId,
        string? filePath,
        Guid? existingFindingId,
        DateTimeOffset now)
    {
        foreach (var s in pool)
        {
            if (Covers(s, componentId, ruleId, filePath, existingFindingId, now)) return true;
        }
        return false;
    }

    // SARIF emitters disagree on whether file paths are URI-encoded (e.g.,
    // "file:///C:/repos/...") or plain. Normalize both sides before
    // comparing so a suppression authored against "src/Foo.cs" matches a
    // finding whose location URI is "file:///C:/repos/x/src/Foo.cs".
    private static bool PathsMatch(string? suppressionPath, string? findingPath)
    {
        if (string.IsNullOrEmpty(suppressionPath) || string.IsNullOrEmpty(findingPath)) return false;
        var a = NormalizePath(suppressionPath);
        var b = NormalizePath(findingPath);
        if (a == b) return true;
        // Tolerate trailing-suffix matches: suppression "src/Foo.cs" should
        // match finding "/C:/repos/x/src/Foo.cs".
        return b.EndsWith("/" + a, StringComparison.Ordinal) || a.EndsWith("/" + b, StringComparison.Ordinal);
    }

    private static string NormalizePath(string p)
    {
        var s = p.Replace('\\', '/');
        if (s.StartsWith("file:///", StringComparison.OrdinalIgnoreCase)) s = s[8..];
        else if (s.StartsWith("file://", StringComparison.OrdinalIgnoreCase)) s = s[7..];
        return s.Trim('/');
    }
}
