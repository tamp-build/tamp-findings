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
        List the clients and projects this token can see. Start here: the other
        tools take project ids from this tree, and a token is scoped down, never
        up — a project-scoped token cannot see its sibling projects, and asking
        for one returns nothing rather than an error.

        The hierarchy is client → project → build. A build is a commit of a
        project; there is no tier between a project and its builds, so a project
        id is the id every other tool wants.
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
                ? "This token's scope contains no projects. It may be scoped to a client that has "
                  + "none yet, or the role it carries cannot view evidence."
                : null,
        };
    }

    [McpServerTool(Name = "get_findings")]
    [Description("""
        Open findings on the latest build of everything this token can see,
        worst severity first. Filter by minimum severity, scanner, commit sha, or
        a path fragment. Returns at most 500 (100 by default) and reports the
        true total: when 'truncated' is true, do NOT state the returned count as
        the number of problems — narrow the filter instead.

        One build per project: the newest canonical one, which is main or master
        with no pull-request ref — the same build the gate judges. Pass a
        commitSha to ask about a different build instead. A project whose only
        builds are from pull-request branches contributes nothing here, because
        "open on main" is the question this answers.

        Three fields carry time, and they are not interchangeable:
        - 'firstSeenInProject' is the finding's real age.
        - 'introducedInThisBuild' is true when the previous canonical build did
          not have it, so the change under review caused it. Null means there is
          no previous build to compare against — not false.
        - 'firstSeen' is only when THIS BUILD saw it, because findings are keyed
          per build. A year-old finding gets a fresh 'firstSeen' on every build
          it survives, so quoting it as "open since" makes old problems look new.

        Severity ranks these; time makes them actionable. A critical that has
        been open for a year is somebody's accepted risk, and a medium this
        commit introduced is this commit's job.
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

    [McpServerTool(Name = "get_gate")]
    [Description("""
        Whether a project's latest build is clear to ship, and what is stopping
        it. Ask this FIRST when you have been sent to fix something: severity is
        not the same thing as a gate, so the worst finding and the thing blocking
        the release are often not the same work.

        Each row is one gate with the evaluator's own 'observed' and 'reason'
        text — the same strings the CLI gate prints, so your account of a failure
        matches the pipeline's. Blocking rows come first.

        Five verdicts, and the difference between them is what to DO:
        - Pass — within threshold.
        - Fail — exceeded. Go fix the finding.
        - Unknown — could not be evaluated, usually because the scanner never
          ran. Blocks, but the remedy is the pipeline, not the code.
        - Error — evaluation itself broke. Blocks; tell an operator.
        - NotApplicable — the gate does not apply to this project's archetype (a
          library cannot run DAST). Ships, and is not a pass.

        'enforcementMode' says whether a blocking gate actually stops a release:
        under Advisory it is recorded and does not block. Do not describe an
        advisory failure as a blocked release.

        The verdict belongs to the commit named in the result. If you have
        changed code since, it is the verdict for the build BEFORE your change —
        say so rather than implying your work has been judged.
        """)]
    public static async Task<object> GetGateAsync(
        AgentReadService reads,
        AgentContext context,
        [Description("The project id, as returned by list_scope.")] Guid projectId,
        CancellationToken ct = default)
    {
        var decision = await reads.GateAsync(context.Require(), projectId, ct);

        if (decision is null)
            return Invalid("That project is outside this token's scope.");

        if (decision.Unavailable is { } why) return new { decision.ProjectId, note = why };

        return new
        {
            decision.ProjectId,
            decision.CommitSha,
            decision.VersionString,
            decision.BuiltAt,
            decision.EnforcementMode,
            decision.ClearToShip,
            decision.Blocking,
            decision.Score,
            decision.Band,
            gates = decision.Gates,
            note = decision.Blocking == 0
                ? "Nothing is blocking. Under Advisory mode that is also true of a build with "
                  + "failing gates, so check enforcementMode before calling a release clear."
                : null,
        };
    }

    [McpServerTool(Name = "get_score")]
    [Description("""
        The project's risk score for its latest build, and which categories are
        costing it. Scores run 0-100 where HIGHER IS WORSE, and the band
        (green/yellow/orange/red) is this instance's own policy, named in the
        result — it is not a universal scale and should not be quoted as one.

        Read the categories, not just the number. 'contribution' is the points a
        category is actually costing, which is the only thing that says where the
        work is. A category marked 'saturated' is at its ceiling: fixing one more
        finding in it moves the score by nothing until the count drops below the
        clamp, so it is usually the wrong place to start.

        A category with enabled=false is NOT scored by this policy — that is
        different from scoring zero, and the advice for each is opposite.

        'unavailable' means the project has never had a canonical build. Unscored
        is not a score of zero and not a clean bill of health.
        """)]
    public static async Task<object> GetScoreAsync(
        AgentReadService reads,
        AgentContext context,
        [Description("The project id, as returned by list_scope.")] Guid projectId,
        CancellationToken ct = default)
    {
        var score = await reads.ScoreAsync(context.Require(), projectId, ct);

        if (score is null)
            return Invalid("That project is outside this token's scope.");

        if (score.Unavailable is { } why) return new { score.ProjectId, note = why };

        return new
        {
            score.ProjectId,
            score.CommitSha,
            score.VersionString,
            score.Score,
            score.Band,
            score.PriorScore,
            score.DeltaPoints,
            score.PolicyName,
            categories = score.Categories,
            note = score.DeltaPoints is > 0
                ? $"The score moved {score.DeltaPoints} points the wrong way against the previous "
                  + "canonical build. Higher is worse."
                : null,
        };
    }

    [McpServerTool(Name = "list_builds")]
    [Description("""
        The project's recent canonical builds, newest first, each with its score,
        the points it moved, and its gate tally. Use it to tell a regression from
        a long-standing problem — a score that has been red for six builds is a
        different conversation from one that went red on the last commit.

        Canonical means main or master, with no pull-request ref: the same builds
        the gate judges. A build from a PR branch is not here.

        Capped at six builds, and the cap is not raisable through this tool —
        every row is a full re-score, so this is the most expensive read on this
        surface. Six is what the dashboard shows.
        """)]
    public static async Task<object> ListBuildsAsync(
        AgentReadService reads,
        AgentContext context,
        [Description("The project id, as returned by list_scope.")] Guid projectId,
        CancellationToken ct = default)
    {
        var history = await reads.BuildsAsync(context.Require(), projectId, ct);

        if (history is null)
            return Invalid("That project is outside this token's scope.");

        if (history.Unavailable is { } why) return new { history.ProjectId, note = why };

        return new
        {
            history.ProjectId,
            builds = history.Builds,
            returned = history.Builds.Count,
            note = history.Builds.Count == 1
                ? "Only one canonical build exists, so no build-over-build movement can be read "
                  + "from this and nothing here attributes a finding to a change."
                : null,
        };
    }

    [McpServerTool(Name = "get_dependencies")]
    [Description("""
        The dependency graph from a project's most recent SBOM: every package,
        the edges between them, and the advisories attached to each. Use it to
        answer "what pulls this in" — the edges are flat (parent purl, child
        purl), so a transitive path is a walk over them.

        Only the newest build's SBOM, and the build it came from is named in the
        result: do not treat it as the graph of code you have since changed.
        Returns not-found when the project has no SBOM or is outside this token's
        scope.
        """)]
    public static async Task<object> GetDependenciesAsync(
        AgentReadService reads,
        AgentContext context,
        [Description("The project id, as returned by list_scope.")] Guid projectId,
        CancellationToken ct = default)
    {
        var graph = await reads.DependenciesAsync(context.Require(), projectId, ct);

        return graph is null
            ? Invalid("No SBOM is available for that project, or it is outside this token's scope.")
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
