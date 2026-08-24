using System.Text.RegularExpressions;

namespace Tamp.Findings.Api.Tests;

// Where a refused sign-in lands, and whether the reader is told why.
//
// A real claim attempt against the cluster was refused — correctly, the token
// had a stray newline — and the operator was dropped on the application root
// with no explanation at all. Three separate faults stacked up to produce that,
// and each one was invisible on its own.
public class SignInFailureTests
{
    [Fact]
    public void A_refused_github_sign_in_lands_on_the_sign_in_page()
    {
        // The GitHub handler carried its own inline OnRemoteFailure that
        // redirected to "/" — written for the React SPA, whose SignInView read
        // ?error= off the root. TFND-128 retired that SPA; the handler outlived
        // it. The OIDC path had been using the shared handler all along, so the
        // two providers failed to different places.
        var auth = Source("src/Tamp.Findings.Api/Authentication/AuthExtensions.cs");

        Assert.DoesNotContain("Redirect($\"/?error=", auth, StringComparison.Ordinal);

        // Every redirect this file performs on a failed round-trip goes to the
        // sign-in page.
        foreach (Match m in Regex.Matches(auth, @"Response\.Redirect\(\$?""([^""]+)"""))
        {
            Assert.StartsWith("/signin", m.Groups[1].Value, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void The_sign_in_page_reads_the_query_name_that_is_actually_sent()
    {
        // The page bound an unnamed [SupplyParameterFromQuery] called Reason,
        // which binds to "reason". Every producer sends "error". So the page
        // held a written explanation for a rejected setup token and could never
        // display it — the parameter was silently always null.
        var page = Source("src/Tamp.Findings.Web/Components/Pages/SignIn.razor");

        Assert.Contains("""[SupplyParameterFromQuery(Name = "error")] public string? Reason""", page, StringComparison.Ordinal);
    }

    [Fact]
    public void Every_failure_reason_has_something_to_say()
    {
        // A reason the page cannot name renders as the generic "sign-in did not
        // complete", which tells the reader nothing they can act on — and the
        // reasons exist precisely to be actionable.
        var auth = Source("src/Tamp.Findings.Api/Authentication/AuthExtensions.cs");
        var page = Source("src/Tamp.Findings.Web/Components/Pages/SignIn.razor");

        // The right-hand side of each arm in FailureReason's switch.
        var body = auth[auth.IndexOf("FailureReason(Exception? failure)", StringComparison.Ordinal)..];
        body = body[..body.IndexOf("};", StringComparison.Ordinal)];

        var reasons = Regex.Matches(body, @"=>\s*""([a-z_]+)""")
            .Select(m => m.Groups[1].Value)
            .Where(r => r != "remote_failure")   // the catch-all IS the generic message
            .Distinct();

        var unhandled = reasons.Where(r => !page.Contains($"\"{r}\" =>", StringComparison.Ordinal)).ToList();

        Assert.True(unhandled.Count == 0,
            "Failure reasons the sign-in page does not explain: " + string.Join(", ", unhandled));
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
