using System.Text.RegularExpressions;

namespace Tamp.Findings.Api.Tests;

// The administrator seat being claimed must leave an audit entry (TFND-140).
//
// This is the root of the access-control trust chain — the one event that
// converts an unclaimed deployment into one with a permanent admin, behind no
// approval and no prior user. It cannot be exercised at runtime here (the claim
// requires "no users at all", which a shared test database cannot present), so
// it is guarded the way the rest of this auth code is: by asserting the write is
// present on both bootstrap paths and cannot be quietly dropped.
public class AdminClaimAuditTests
{
    [Fact]
    public void The_first_run_claim_records_the_seat_as_an_access_event()
    {
        var src = Source("src/Tamp.Findings.Api/Authentication/ExternalSignIn.cs");

        // The write lives inside the first-user branch, so a claim cannot commit
        // without it.
        var claimBlock = Between(src, "if (isFirstUser)", "await db.SaveChangesAsync(ct);");

        Assert.Contains("AdminSeatClaimed", claimBlock, StringComparison.Ordinal);
        Assert.Contains("RecordSystem", claimBlock, StringComparison.Ordinal);
        Assert.Contains("AuditClass.Access", claimBlock, StringComparison.Ordinal);
        // The evidence an assessor asks for: who, via which provider.
        Assert.Contains("profile.Login", claimBlock, StringComparison.Ordinal);
        Assert.Contains("profile.Scheme", claimBlock, StringComparison.Ordinal);
    }

    [Fact]
    public void The_bootstrap_env_promotion_is_also_recorded()
    {
        // The GITHUB_BOOTSTRAP_ADMIN_LOGIN path is an equally privileged, equally
        // unrecorded transition — it has to be covered by the same landing.
        var src = Source("src/Tamp.Findings.Api/Authentication/AuthExtensions.cs");

        // The promotion sets IsAdmin and, right after, records it before the save.
        var body = Between(src, "user.IsAdmin = true;", "await db.SaveChangesAsync(ct);");

        Assert.Contains("AdminBootstrapPromoted", body, StringComparison.Ordinal);
        Assert.Contains("RecordSystem", body, StringComparison.Ordinal);
    }

    [Fact]
    public void Both_actions_exist_as_distinct_audit_constants()
    {
        // "A distinct action, not a generic user-created row" — the ticket's
        // acceptance criterion. Distinct constants are what makes them filterable.
        var audit = Source("src/Tamp.Findings.Application/Auditing/AuditLog.cs");

        Assert.Contains("AdminSeatClaimed = \"admin.seat_claimed\"", audit, StringComparison.Ordinal);
        Assert.Contains("AdminBootstrapPromoted = \"admin.bootstrap_promoted\"", audit, StringComparison.Ordinal);
    }

    private static string Between(string text, string start, string end)
    {
        var a = text.IndexOf(start, StringComparison.Ordinal);
        Assert.True(a >= 0, $"marker not found: {start}");
        var b = text.IndexOf(end, a, StringComparison.Ordinal);
        Assert.True(b > a, $"end marker not found after start: {end}");
        return text[a..b];
    }

    private static string Source(string relativePath)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !Directory.Exists(Path.Combine(dir.FullName, "src")))
            dir = dir.Parent;

        Assert.NotNull(dir);
        var full = Path.Combine(dir!.FullName, relativePath.Replace('/', Path.DirectorySeparatorChar));
        Assert.True(File.Exists(full), $"not found: {full}");
        return File.ReadAllText(full);
    }
}
