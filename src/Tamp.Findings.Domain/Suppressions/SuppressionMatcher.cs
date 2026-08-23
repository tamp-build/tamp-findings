using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Domain.Suppressions;

/// <summary>
/// Where a finding sits, for the purpose of deciding whether a suppression
/// reaches it (TFND-132).
///
/// A record rather than three loose parameters, because the previous signature
/// took a bare componentId and that is exactly how the tenant came to be
/// missing from the predicate: there was nowhere to put it that a caller would
/// have to fill in.
/// </summary>
public readonly record struct SuppressionTarget(Guid ClientId, Guid ProjectId, Guid ComponentId);

// Pure-domain decision helper: does any active suppression in `pool` cover
// the given finding? Used by the ingest path to set Status=Suppressed
// during upsert. Kept out of the Data project so the rule stays
// reviewable without spelunking through EF.
public static class SuppressionMatcher
{
    public static bool Covers(
        Suppression s,
        SuppressionTarget target,
        string ruleId,
        string? filePath,
        Guid? existingFindingId,
        DateTimeOffset now)
    {
        // Active = no expiry or expiry still in the future.
        if (s.ExpiresAt is { } exp && exp <= now) return false;

        // TENANT FIRST, before any scope-specific rule (TFND-132).
        //
        // Without this, RuleOnFile and RuleEverywhere matched on rule id alone
        // and silenced a rule for every client on the instance. The check is
        // here rather than inside each case because it applies to all of them
        // and a per-case check is one new case away from being forgotten.
        if (!SameTenant(s, target)) return false;

        return s.Scope switch
        {
            SuppressionScope.SingleFinding =>
                existingFindingId is { } id && s.FindingId == id,

            SuppressionScope.RuleOnFile =>
                string.Equals(s.RuleId, ruleId, StringComparison.Ordinal)
                && PathsMatch(s.FilePath, filePath),

            SuppressionScope.RuleOnComponent =>
                string.Equals(s.RuleId, ruleId, StringComparison.Ordinal)
                && s.ComponentId == target.ComponentId,

            SuppressionScope.RuleEverywhere =>
                string.Equals(s.RuleId, ruleId, StringComparison.Ordinal),

            _ => false,
        };
    }

    public static bool AnyCovers(
        IEnumerable<Suppression> pool,
        SuppressionTarget target,
        string ruleId,
        string? filePath,
        Guid? existingFindingId,
        DateTimeOffset now)
    {
        foreach (var s in pool)
        {
            if (Covers(s, target, ruleId, filePath, existingFindingId, now)) return true;
        }
        return false;
    }

    /// <summary>
    /// Does this suppression belong to the tenant the finding is in?
    ///
    /// A row with no ClientId is a LEGACY row, written before suppressions
    /// carried one, and it keeps its old instance-wide behaviour. Retroactively
    /// narrowing those would silently un-suppress findings people have already
    /// signed off — a compliance claim changing under them with no action on
    /// their part, which is worse than the defect. New rows always carry a
    /// client, so the legacy set only shrinks.
    /// </summary>
    private static bool SameTenant(Suppression s, SuppressionTarget target)
    {
        if (s.ClientId is null) return true;
        if (s.ClientId != target.ClientId) return false;

        // A project-scoped row does not reach a sibling project; a row with no
        // project reaches everything under its client, which is what a
        // client-tier author meant.
        return s.ProjectId is null || s.ProjectId == target.ProjectId;
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
