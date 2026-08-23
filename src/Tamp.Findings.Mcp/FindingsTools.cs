using System.ComponentModel;
using ModelContextProtocol.Server;
using Tamp.Findings.Application.Mcp;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Mcp;

/// <summary>
/// The tools an agent gets (TFND-12 / F11.3).
///
/// Thin on purpose. Every method here does two things: turn loose tool
/// arguments into a typed request, and hand it to <see cref="AgentReadService"/>
/// — which is where the token's scope is applied. No query lives in this class,
/// because a query in this class would be a query that skipped the scope check.
///
/// The descriptions matter as much as the code. They are the only documentation
/// the model on the other end will ever read, so each one says what the tool
/// answers AND what it does not, which is how an agent avoids reporting a
/// truncated list as a complete one.
/// </summary>
[McpServerToolType]
public sealed class FindingsTools
{
    // Not a static class, only because WithTools<T> cannot take one as a type
    // argument. Explicit registration is worth that: assembly scanning would
    // expose any tool type added later without anyone deciding to, and on a
    // read surface over other people's findings that decision should be typed
    // out.
    private FindingsTools() { }

    [McpServerTool(Name = "list_scope")]
    [Description("""
        List the clients, projects and components this token can see. Start here:
        the other tools take ids from this tree, and a token is scoped down, never
        up — a component-scoped token cannot see its siblings, and asking for one
        returns nothing rather than an error.
        """)]
    public static async Task<object> ListScopeAsync(
        AgentReadService reads,
        AgentContext context,
        CancellationToken ct = default)
    {
        var scope = await reads.ScopeAsync(context.Require(), ct);

        return new
        {
            projects = scope,
            // Said explicitly rather than left as an empty array. An agent that
            // sees nothing should know the difference between "this instance is
            // empty" and "your token does not reach anything".
            note = scope.Count == 0
                ? "This token's scope contains no components. It may be scoped to a project that "
                  + "has none yet, or the role it carries cannot view evidence."
                : null,
        };
    }

    [McpServerTool(Name = "get_findings")]
    [Description("""
        Open findings across everything this token can see, worst severity first.
        Filter by minimum severity, scanner, commit sha, or a path fragment.
        Returns at most 500 (100 by default) and reports the true total: when
        'truncated' is true, do NOT state the returned count as the number of
        problems — narrow the filter instead.
        """)]
    public static async Task<object> GetFindingsAsync(
        AgentReadService reads,
        AgentContext context,
        [Description("Minimum severity: Critical, High, Medium, Low, or Info. Omit for all.")]
        string? minimumSeverity = null,
        [Description("Scanner that produced it, e.g. OpenGrep, Trivy, Zap. Omit for all.")]
        string? scanner = null,
        [Description("Only findings from the build at this commit sha. Omit for the latest of each.")]
        string? commitSha = null,
        [Description("Only findings whose file path contains this fragment.")]
        string? pathContains = null,
        [Description("How many to return, 1-500. Defaults to 100.")]
        int? limit = null,
        CancellationToken ct = default)
    {
        // An unparseable filter is refused rather than ignored. Silently
        // dropping "minimumSeverity: Criticall" would return every Info finding
        // in the tree and look like a complete answer to the question asked.
        if (!TryParse<Severity>(minimumSeverity, out var severity))
            return Invalid($"'{minimumSeverity}' is not a severity. Use {Names<Severity>()}.");

        if (!TryParse<ScannerKind>(scanner, out var kind))
            return Invalid($"'{scanner}' is not a scanner this instance knows. Use {Names<ScannerKind>()}.");

        var page = await reads.FindingsAsync(
            context.Require(),
            new AgentFindingsFilter(severity, kind, commitSha, pathContains, limit),
            ct);

        if (page.Refusal is { } refusal) return Invalid(refusal);

        return new
        {
            findings = page.Findings,
            returned = page.Findings.Count,
            total = page.Total,
            truncated = page.Truncated,
            note = page.Truncated
                ? $"Showing {page.Findings.Count} of {page.Total}. This is a filtered view, not "
                  + "the whole set — say \"at least\" or narrow the filter before counting."
                : null,
        };
    }

    [McpServerTool(Name = "get_finding")]
    [Description("""
        One finding in full, with the surrounding source when this instance holds
        it. Code context is only available for files a coverage report brought in
        — for everything else 'context' is null and 'snippet' is whatever the
        scanner captured. A finding outside this token's scope returns not-found,
        which is not the same as it not existing.
        """)]
    public static async Task<object> GetFindingAsync(
        AgentReadService reads,
        AgentContext context,
        [Description("The finding id, as returned by get_findings.")] Guid findingId,
        [Description("Lines of source either side of the flagged line, 0-200. Defaults to 12.")]
        int contextLines = 12,
        CancellationToken ct = default)
    {
        var detail = await reads.FindingAsync(context.Require(), findingId, contextLines, ct);

        if (detail is null)
            return Invalid("No finding with that id is visible to this token.");

        return new
        {
            finding = detail,
            note = detail.Context is null && detail.FilePath is { Length: > 0 }
                ? "No stored source for this file, so there is no code context. This instance only "
                  + "holds source for files a coverage report included — read the file from the "
                  + "repository instead of inferring it from the snippet."
                : null,
        };
    }

    [McpServerTool(Name = "get_dependencies")]
    [Description("""
        The dependency graph from a component's most recent SBOM: every package,
        the edges between them, and the advisories attached to each. Use it to
        answer "what pulls this in" — the edges are flat (parent purl, child
        purl), so a transitive path is a walk over them. Returns not-found when
        the component has no SBOM or is outside this token's scope.
        """)]
    public static async Task<object> GetDependenciesAsync(
        AgentReadService reads,
        AgentContext context,
        [Description("The component id, as returned by list_scope.")] Guid componentId,
        CancellationToken ct = default)
    {
        var graph = await reads.DependenciesAsync(context.Require(), componentId, ct);

        return graph is null
            ? Invalid("No SBOM is available for that component, or it is outside this token's scope.")
            : new { graph, packages = graph.Packages.Count, edges = graph.Edges.Count };
    }

    [McpServerTool(Name = "get_suppressions")]
    [Description("""
        What has already been muted on a project, and why — both suppressions (a
        person silenced this finding) and VEX statements (this CVE does not reach
        us, with the argument). Read this BEFORE proposing remediation: a finding
        that is suppressed has already been decided, and an expired suppression
        (marked 'expired') is the one case where re-raising it is the right move.
        """)]
    public static async Task<object> GetSuppressionsAsync(
        AgentReadService reads,
        AgentContext context,
        [Description("The project id, as returned by list_scope.")] Guid projectId,
        CancellationToken ct = default)
    {
        var state = await reads.SuppressionsAsync(
            context.Require(), projectId, DateTimeOffset.UtcNow, ct);

        if (state is null)
            return Invalid("That project is outside this token's scope.");

        return new
        {
            suppressions = state.Suppressions,
            vex = state.Vex,
            note = state.Suppressions.Count == 0 && state.Vex.Count == 0
                ? "Nothing is suppressed on this project. Every open finding is genuinely open."
                : null,
        };
    }

    // ---- Helpers ------------------------------------------------------------

    /// <summary>
    /// A refusal the model can act on.
    ///
    /// Shaped as an ordinary result rather than thrown: an exception reaches the
    /// agent as a protocol error with no room for the sentence that says what to
    /// do instead, and "the tool failed" is the least useful thing it could be
    /// told.
    /// </summary>
    private static object Invalid(string reason) => new { error = reason };

    private static bool TryParse<T>(string? value, out T? parsed) where T : struct, Enum
    {
        parsed = null;
        if (string.IsNullOrWhiteSpace(value)) return true;

        if (!Enum.TryParse<T>(value, ignoreCase: true, out var result)) return false;

        parsed = result;
        return true;
    }

    private static string Names<T>() where T : struct, Enum =>
        string.Join(", ", Enum.GetNames<T>());
}
