using System.Reflection;
using System.Text.RegularExpressions;
using ModelContextProtocol.Server;
using Tamp.Findings.Mcp;

namespace Tamp.Findings.Integration.Tests;

/// <summary>
/// The documented tool surface has to be the real one.
///
/// Three audits in this epic found the same class of defect — a guarantee kept
/// only by prose. The tool descriptions said "component" for weeks after the
/// tier was removed (TFND-235), the InfoSecOfficer rule was enforced only by a
/// dropdown (TFND-242), and "there is no write path" survived the arrival of
/// two writes. Every one of those was found by a person reading carefully, which
/// is not a control.
///
/// So this is the control. It needs no database: it reflects over
/// <see cref="FindingsTools"/> and reads the shipped Markdown, which is exactly
/// the pair that drifts.
/// </summary>
public class AppCovMcpDocsMatchSurfaceTests
{
    private static readonly string[] Docs = ["README.md", "docs/AGENT-ACCESS.md"];

    /// <summary>
    /// Walk up from the test assembly to the directory holding the solution.
    /// Tests run out of bin/Debug/netX, and hard-coding the hop count breaks the
    /// first time the layout moves.
    /// </summary>
    private static DirectoryInfo RepoRoot()
    {
        var dir = new DirectoryInfo(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location)!);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "README.md")))
            dir = dir.Parent;

        Assert.NotNull(dir);
        return dir!;
    }

    private static IReadOnlyList<string> RegisteredTools() =>
        typeof(FindingsTools)
            .GetMethods(BindingFlags.Public | BindingFlags.Static)
            .Select(m => m.GetCustomAttribute<McpServerToolAttribute>())
            .Where(a => a is not null)
            .Select(a => a!.Name!)
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToArray();

    private static HashSet<string> DocumentedTools(string markdown) =>
        Regex.Matches(markdown, @"\|\s*`([a-z_]+)`\s*\|")
            .Select(m => m.Groups[1].Value)
            .ToHashSet(StringComparer.Ordinal);

    [Theory]
    [InlineData("README.md")]
    [InlineData("docs/AGENT-ACCESS.md")]
    public void Every_registered_tool_appears_in_the_documented_table(string relativePath)
    {
        var markdown = File.ReadAllText(Path.Combine(RepoRoot().FullName, relativePath));
        var documented = DocumentedTools(markdown);

        var missing = RegisteredTools().Where(t => !documented.Contains(t)).ToArray();

        Assert.True(missing.Length == 0,
            $"{relativePath} does not document: {string.Join(", ", missing)}. The tool tables are "
            + "what an operator reads to decide what an agent can do; a tool missing from them is a "
            + "capability nobody signed off.");
    }

    [Theory]
    [InlineData("README.md")]
    [InlineData("docs/AGENT-ACCESS.md")]
    public void The_documented_table_invents_no_tool_that_does_not_exist(string relativePath)
    {
        var markdown = File.ReadAllText(Path.Combine(RepoRoot().FullName, relativePath));
        var registered = RegisteredTools().ToHashSet(StringComparer.Ordinal);

        var phantom = DocumentedTools(markdown).Where(t => !registered.Contains(t)).ToArray();

        Assert.True(phantom.Length == 0,
            $"{relativePath} documents tools that do not exist: {string.Join(", ", phantom)}. An "
            + "agent told about a tool it does not have will report the failure as a product fault.");
    }

    [Fact]
    public void Every_tool_carries_a_description_substantial_enough_to_be_documentation()
    {
        // The descriptions are the ONLY documentation the model on the other end
        // ever reads. A thin one is not a style problem; it is the difference
        // between an agent that knows a count is capped and one that reports a
        // truncated list as complete.
        var thin = typeof(FindingsTools)
            .GetMethods(BindingFlags.Public | BindingFlags.Static)
            .Where(m => m.GetCustomAttribute<McpServerToolAttribute>() is not null)
            .Select(m => new
            {
                Name = m.GetCustomAttribute<McpServerToolAttribute>()!.Name,
                Description = m.GetCustomAttribute<System.ComponentModel.DescriptionAttribute>()?.Description ?? "",
            })
            .Where(x => x.Description.Trim().Length < 120)
            .Select(x => x.Name)
            .ToArray();

        Assert.True(thin.Length == 0,
            $"These tools have no usable description: {string.Join(", ", thin)}");
    }

    [Theory]
    [InlineData("README.md")]
    [InlineData("docs/AGENT-ACCESS.md")]
    public void The_docs_do_not_still_claim_the_surface_is_read_only(string relativePath)
    {
        // "There is no write path" was true for two months and then was not, and
        // it is the single sentence an operator is most likely to rely on. It
        // cannot be allowed back by accident.
        var markdown = File.ReadAllText(Path.Combine(RepoRoot().FullName, relativePath));

        foreach (var claim in new[] { "no write path", "they can never write", "cannot write" })
        {
            Assert.DoesNotContain(claim, markdown, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public void The_component_tier_is_gone_from_everything_an_agent_reads()
    {
        // TFND-235: the tool descriptions told the model to pass a component id
        // for weeks after the tier was removed, and the descriptions are the only
        // documentation it gets. "SbomComponent" and the EF column names are
        // legitimate — SBOM packages are components — so this looks only at the
        // agent-facing text.
        var tools = typeof(FindingsTools)
            .GetMethods(BindingFlags.Public | BindingFlags.Static)
            .Where(m => m.GetCustomAttribute<McpServerToolAttribute>() is not null)
            .ToArray();

        // Both the tool descriptions and the per-parameter ones: the stale
        // "component id" that started this was on a PARAMETER.
        var descriptions = new List<(string Name, string Text)>();
        foreach (var m in tools)
        {
            var tool = m.GetCustomAttribute<McpServerToolAttribute>()!.Name ?? m.Name;
            descriptions.Add((tool,
                m.GetCustomAttribute<System.ComponentModel.DescriptionAttribute>()?.Description ?? ""));

            foreach (var pa in m.GetParameters())
            {
                descriptions.Add(($"{tool}({pa.Name})",
                    pa.GetCustomAttribute<System.ComponentModel.DescriptionAttribute>()?.Description ?? ""));
            }
        }

        var offenders = descriptions
            .Where(d => d.Text.Contains("component", StringComparison.OrdinalIgnoreCase))
            .Select(d => d.Name)
            .ToArray();

        Assert.True(offenders.Length == 0,
            "The Component tier was removed in TFND-205/207. These agent-facing descriptions still "
            + $"mention it: {string.Join(", ", offenders)}");
    }
}
