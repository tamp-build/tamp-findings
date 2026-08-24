using System.Text.RegularExpressions;

namespace Tamp.Findings.Api.Tests;

// WCAG 2.4.2 Page Titled, enforced against the source rather than against a
// running browser.
//
// The dogfood axe-core leg found the original defect — an untitled document at
// the anonymous root — but only after a full CI cycle, and only for the one URL
// it happened to scan. A source scan states the rule for every route at once
// and fails in seconds.
public class PageTitleTests
{
    [Fact]
    public void Every_routable_page_declares_a_title()
    {
        // A page with no <PageTitle> emits no <title> at all: HeadOutlet
        // renders whatever the page supplies and there is no default in
        // App.razor. The tab then reads as the bare URL, which is what a
        // screen reader announces when moving between windows.
        var offenders = RazorFiles()
            .Where(f => Regex.IsMatch(File.ReadAllText(f), @"^@page\s", RegexOptions.Multiline))
            .Where(f => !File.ReadAllText(f).Contains("<PageTitle", StringComparison.Ordinal))
            .Select(Path.GetFileName)
            .ToList();

        Assert.True(offenders.Count == 0,
            "Routable components with no <PageTitle> — every route needs one (WCAG 2.4.2):\n  "
            + string.Join("\n  ", offenders));
    }

    [Theory]
    [InlineData("NotAuthorized")]
    [InlineData("NotFound")]
    public void Router_fallback_declares_a_title(string section)
    {
        // These two are the easy ones to miss, and the most likely to be seen
        // by someone who needs the title most.
        //
        // They render INSTEAD of the page component, so the page's own
        // <PageTitle> never runs — a route can be perfectly titled when signed
        // in and untitled when signed out. NotAuthorized is what every
        // signed-out visitor following a deep link gets, and it was untitled
        // in production until axe-core flagged it.
        var routes = File.ReadAllText(Path.Combine(WebRoot(), "Components", "Routes.razor"));

        var block = Regex.Match(routes, $@"<{section}>(.*?)</{section}>", RegexOptions.Singleline);
        Assert.True(block.Success, $"<{section}> block not found in Routes.razor — was the router restructured?");

        Assert.True(block.Groups[1].Value.Contains("<PageTitle", StringComparison.Ordinal),
            $"The <{section}> router fallback renders without a <PageTitle>, so it produces an "
            + "untitled document. It replaces the page component, so the page's own title does not apply.");
    }

    private static IEnumerable<string> RazorFiles() =>
        Directory.EnumerateFiles(Path.Combine(WebRoot(), "Components"), "*.razor", SearchOption.AllDirectories);

    private static string WebRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !Directory.Exists(Path.Combine(dir.FullName, "src", "Tamp.Findings.Web")))
            dir = dir.Parent;

        Assert.NotNull(dir);
        return Path.Combine(dir!.FullName, "src", "Tamp.Findings.Web");
    }
}
