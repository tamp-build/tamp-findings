using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Application.Mcp;

/// <summary>
/// Everything an agent can read, and nothing else (TFND-12 / F11.3).
///
/// One class rather than letting the tool layer reach into the ordinary
/// queries, for one reason: every method here starts by resolving the token's
/// scope to a concrete set of component ids and then filters on it. If the tool
/// layer could call <c>FindingsExplorerQuery</c> directly it would be passing a
/// projectId the agent supplied, and the scoping rule would hold only as long
/// as every future tool remembered to check — which is to say, not for long.
///
/// Reads only. There is deliberately no write path: an agent that can file a
/// suppression can retire a finding it was asked to fix, and the whole value of
/// this product is that the evidence is not negotiable.
/// </summary>
public sealed class AgentReadService
{
    private readonly FindingsDbContext _db;
    private readonly CapabilityEvaluator _capabilities;

    public AgentReadService(FindingsDbContext db, CapabilityEvaluator capabilities)
    {
        _db = db;
        _capabilities = capabilities;
    }

    /// <summary>
    /// The components this identity may see, as the hierarchy the agent should
    /// reason about.
    ///
    /// Returned rather than assumed, because an agent given a client-scoped
    /// token has no other way to learn what projects exist — and guessing names
    /// at the other tools would just be a slower way to be told no.
    /// </summary>
    public async Task<IReadOnlyList<AgentScopeNode>> ScopeAsync(
        AgentIdentity agent, CancellationToken ct = default)
    {
        if (Denied(agent) is not null) return [];

        var rows = await Visible(agent)
            .Select(c => new
            {
                ComponentId = c.Id,
                ComponentName = c.Name,
                c.Kind,
                ProjectId = c.Project!.Id,
                ProjectName = c.Project!.Name,
                ClientName = c.Project!.Client!.Name,
            })
            .ToArrayAsync(ct);

        return rows
            .GroupBy(r => new { r.ClientName, r.ProjectId, r.ProjectName })
            .Select(g => new AgentScopeNode(
                g.Key.ClientName, g.Key.ProjectId, g.Key.ProjectName,
                g.Select(c => new AgentComponent(c.ComponentId, c.ComponentName, c.Kind))
                 .OrderBy(c => c.Name, StringComparer.OrdinalIgnoreCase)
                 .ToArray()))
            .OrderBy(p => p.Client, StringComparer.OrdinalIgnoreCase)
            .ThenBy(p => p.Project, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    /// <summary>
    /// Open findings across the agent's scope, worst first.
    ///
    /// Capped, and the cap is REPORTED. An agent that silently receives the
    /// first 200 of 5,000 findings will confidently tell someone the codebase
    /// has 200 problems, and that answer is worse than no answer — it is a
    /// wrong number carrying this product's name.
    /// </summary>
    public async Task<AgentFindingsPage> FindingsAsync(
        AgentIdentity agent, AgentFindingsFilter filter, CancellationToken ct = default)
    {
        if (Denied(agent) is { } reason) return AgentFindingsPage.Refused(reason);

        var components = await VisibleIdsAsync(agent, ct);
        if (components.Count == 0) return AgentFindingsPage.Empty;

        var query =
            from f in _db.Findings.AsNoTracking()
            join cv in _db.ComponentVersions.AsNoTracking() on f.ComponentVersionId equals cv.Id
            where components.Contains(cv.ComponentId) && f.Status == FindingStatus.Open
            select new { f, cv };

        if (filter.Severity is { } minimum)
            query = query.Where(r => r.f.Severity >= minimum);

        if (filter.Scanner is { } scanner)
            query = query.Where(r => r.f.Scanner == scanner);

        if (filter.CommitSha is { Length: > 0 } sha)
            query = query.Where(r => r.cv.CommitSha == sha);

        if (filter.PathContains is { Length: > 0 } fragment)
            query = query.Where(r => r.f.FilePath != null && r.f.FilePath.Contains(fragment));

        // Counted before the take, so the cap can say what it cut. One extra
        // round trip is a fair price for not lying about the total.
        var total = await query.CountAsync(ct);

        var take = Math.Clamp(filter.Limit ?? 100, 1, 500);

        var rows = await query
            .OrderByDescending(r => r.f.Severity)
            .ThenBy(r => r.f.FilePath)
            .ThenBy(r => r.f.Line)
            .Take(take)
            .Select(r => new AgentFinding(
                r.f.Id, r.f.Scanner, r.f.RuleId, r.f.Severity, r.f.Title,
                r.f.FilePath, r.f.Line, r.f.Purl, r.f.FirstSeen))
            .ToArrayAsync(ct);

        return new AgentFindingsPage(rows, total, total > rows.Length, null);
    }

    /// <summary>
    /// One finding, with the surrounding source when this product happens to
    /// hold it.
    ///
    /// The id is checked against the agent's scope rather than trusted. A
    /// finding id is a guid an agent could have been handed by anyone, and
    /// "looks like one of ours" is not authorization.
    /// </summary>
    public async Task<AgentFindingDetail?> FindingAsync(
        AgentIdentity agent, Guid findingId, int contextLines = 12, CancellationToken ct = default)
    {
        if (Denied(agent) is not null) return null;

        var components = await VisibleIdsAsync(agent, ct);

        var row = await (
            from f in _db.Findings.AsNoTracking()
            join cv in _db.ComponentVersions.AsNoTracking() on f.ComponentVersionId equals cv.Id
            join c in _db.Components.AsNoTracking() on cv.ComponentId equals c.Id
            where f.Id == findingId && components.Contains(cv.ComponentId)
            select new
            {
                f.Id, f.Scanner, f.RuleId, f.Severity, f.Title, f.Description,
                f.FilePath, f.Line, f.Snippet, f.Purl, f.FirstSeen, f.LastSeen,
                Component = c.Name, c.ProjectId, cv.CommitSha, cv.VersionString,
            }).SingleOrDefaultAsync(ct);

        // Null for "not yours" as well as "no such thing". Distinguishing them
        // would confirm the existence of a finding outside the agent's scope,
        // which is the one bit this surface is supposed to withhold.
        if (row is null) return null;

        var context = row.FilePath is { Length: > 0 } path && row.Line is { } line
            ? await ContextAsync(row.ProjectId, path, line, contextLines, ct)
            : null;

        // The snippet the scanner captured is kept even when full context
        // exists: it is what the tool actually flagged, which is not always
        // what the file says today.
        return new AgentFindingDetail(
            row.Id, row.Scanner, row.RuleId, row.Severity, row.Title, row.Description,
            row.FilePath, row.Line, row.Snippet, row.Purl, row.Component,
            row.CommitSha, row.VersionString, row.FirstSeen, row.LastSeen, context);
    }

    /// <summary>
    /// The dependency graph for one component's newest SBOM, as flat edges plus
    /// the packages they connect.
    ///
    /// Flat rather than nested: the question an agent asks here is "what pulls
    /// this in", and answering it from a tree means walking the whole tree,
    /// whereas the edge list answers it directly. The caller can nest if it
    /// wants to.
    /// </summary>
    public async Task<AgentDependencyGraph?> DependenciesAsync(
        AgentIdentity agent, Guid componentId, CancellationToken ct = default)
    {
        if (Denied(agent) is not null) return null;

        var components = await VisibleIdsAsync(agent, ct);
        if (!components.Contains(componentId)) return null;

        var snapshot = await (
            from s in _db.SbomSnapshots.AsNoTracking()
            join cv in _db.ComponentVersions.AsNoTracking() on s.ComponentVersionId equals cv.Id
            where cv.ComponentId == componentId
            orderby cv.CreatedAt descending
            select new { s.Id, s.ToolName, cv.CommitSha, cv.CreatedAt })
            .FirstOrDefaultAsync(ct);

        if (snapshot is null) return null;

        var packages = await _db.SbomComponents.AsNoTracking()
            .Where(c => c.SbomSnapshotId == snapshot.Id)
            .Select(c => new { c.Id, c.Purl, c.Name, c.Version, c.License, c.Kind, c.LatestVersion })
            .ToArrayAsync(ct);

        var edges = await _db.SbomDependencies.AsNoTracking()
            .Where(d => d.SbomSnapshotId == snapshot.Id)
            .Select(d => new { d.ParentComponentId, d.ChildComponentId })
            .ToArrayAsync(ct);

        // Vulnerabilities attached to the packages, so an agent asking for the
        // graph does not then have to ask about each node in turn. This is the
        // question it was going to ask next.
        var vulnerable = await _db.Vulnerabilities.AsNoTracking()
            .Where(v => v.SbomComponent!.SbomSnapshotId == snapshot.Id)
            .Select(v => new { v.SbomComponentId, v.AdvisoryId, v.Severity })
            .ToArrayAsync(ct);

        var byId = packages.ToDictionary(p => p.Id, p => p.Purl);
        var advisories = vulnerable
            .GroupBy(v => v.SbomComponentId)
            .ToDictionary(
                g => g.Key,
                g => g.OrderByDescending(v => v.Severity).Select(v => v.AdvisoryId).ToArray());

        var nodes = packages
            .Select(p => new AgentPackage(
                p.Purl, p.Name, p.Version, p.License, p.Kind, p.LatestVersion,
                advisories.TryGetValue(p.Id, out var ids) ? ids : []))
            .OrderBy(p => p.Purl, StringComparer.Ordinal)
            .ToArray();

        // Edges whose endpoints are missing are dropped rather than emitted
        // with nulls. A dangling edge is an ingest defect, and passing it
        // through would make it an agent's problem to interpret.
        var links = edges
            .Where(e => byId.ContainsKey(e.ParentComponentId) && byId.ContainsKey(e.ChildComponentId))
            .Select(e => new AgentDependencyEdge(byId[e.ParentComponentId], byId[e.ChildComponentId]))
            .ToArray();

        return new AgentDependencyGraph(
            componentId, snapshot.CommitSha, snapshot.ToolName, snapshot.CreatedAt, nodes, links);
    }

    /// <summary>
    /// What has been suppressed, and why (F11.3).
    ///
    /// Both mechanisms, because they answer the same question and an agent that
    /// saw only one would propose work that has already been declined:
    /// suppressions (a person muted this finding) and VEX statements (this CVE
    /// does not reach us, and here is the argument).
    ///
    /// Expired suppressions are included and MARKED. A suppression that lapsed
    /// is exactly the case where "why is this still open" has a real answer.
    ///
    /// One remaining case, now a shrinking one: suppressions written before
    /// TFND-132 carry no client at all. <c>SuppressionMatcher</c> keeps their
    /// original instance-wide behaviour — retroactively narrowing them would
    /// silently un-suppress findings people have already signed off — so they
    /// genuinely silence this project and cannot be filtered out without
    /// telling an agent a finding is open when ingest suppresses it.
    ///
    /// They are returned marked <c>InstanceWide</c>, with the reason and the
    /// author withheld, because there is no record of which client wrote them.
    /// "This rule is muted here" is a fact about the caller's own project;
    /// whose decision it was is not the caller's to read. Every row written
    /// since TFND-132 carries a tenant, so this set only shrinks.
    /// </summary>
    public async Task<AgentSuppressionState?> SuppressionsAsync(
        AgentIdentity agent, Guid projectId, DateTimeOffset asOf, CancellationToken ct = default)
    {
        if (Denied(agent) is not null) return null;

        var components = await VisibleIdsAsync(agent, ct);

        var visibleProject = await _db.Components.AsNoTracking()
            .AnyAsync(c => c.ProjectId == projectId && components.Contains(c.Id), ct);
        if (!visibleProject) return null;

        // Anchored in this scope: the caller's own, reason and author included.
        var anchored = await (
            from s in _db.Suppressions.AsNoTracking()
            join f in _db.Findings.AsNoTracking() on s.FindingId equals f.Id
            join cv in _db.ComponentVersions.AsNoTracking() on f.ComponentVersionId equals cv.Id
            where s.FindingId != null && components.Contains(cv.ComponentId)
            select s).ToArrayAsync(ct);

        var componentAnchored = await _db.Suppressions.AsNoTracking()
            .Where(s => s.ComponentId != null && components.Contains(s.ComponentId.Value))
            .ToArrayAsync(ct);

        // Rule-scoped rows that belong to this project, or to its client.
        var clientId = await _db.Projects.AsNoTracking()
            .Where(p => p.Id == projectId)
            .Select(p => (Guid?)p.ClientId)
            .SingleOrDefaultAsync(ct);

        var ruleScoped = await _db.Suppressions.AsNoTracking()
            .Where(s => s.FindingId == null && s.ComponentId == null && s.ClientId != null
                        && s.ClientId == clientId
                        && (s.ProjectId == null || s.ProjectId == projectId))
            .ToArrayAsync(ct);

        // Legacy: written before suppressions carried a tenant. Still applies
        // here, and there is no record of who asked for it.
        var legacy = await _db.Suppressions.AsNoTracking()
            .Where(s => s.FindingId == null && s.ComponentId == null && s.ClientId == null)
            .ToArrayAsync(ct);

        var mine = anchored.Concat(componentAnchored).Concat(ruleScoped).ToArray();

        var authorIds = mine.Select(s => s.CreatedByUserId).Distinct().ToArray();
        var authors = await _db.Users.AsNoTracking()
            .Where(u => authorIds.Contains(u.Id))
            .Select(u => new { u.Id, u.DisplayName })
            .ToArrayAsync(ct);
        var names = authors.ToDictionary(a => a.Id, a => a.DisplayName);

        var suppressions = mine
            .Select(s => new AgentSuppression(
                s.Id, s.Scope, s.RuleId, s.FilePath, s.FindingId, s.Reason,
                names.TryGetValue(s.CreatedByUserId, out var name) ? name : "(unknown)",
                s.CreatedByRole, s.CreatedAt, s.ExpiresAt,
                s.ExpiresAt is not null && s.ExpiresAt <= asOf,
                InstanceWide: false))
            .Concat(legacy.Select(s => new AgentSuppression(
                s.Id, s.Scope, s.RuleId, s.FilePath, s.FindingId,
                // The rule and the expiry are the operative facts and they are
                // about this project. Whose decision it was, nothing records.
                "(written before suppressions carried a tenant — author unknown)",
                "(withheld)",
                s.CreatedByRole, s.CreatedAt, s.ExpiresAt,
                s.ExpiresAt is not null && s.ExpiresAt <= asOf,
                InstanceWide: true)))
            .OrderBy(s => s.Expired)
            .ThenBy(s => s.InstanceWide)
            .ThenByDescending(s => s.CreatedAt)
            .ToArray();

        var vex = await _db.VexStatements.AsNoTracking()
            .Where(v => v.ProjectId == projectId && v.RetiredAt == null)
            .Select(v => new AgentVexStatement(
                v.AdvisoryId, v.Purl, v.Status, v.Justification, v.ImpactStatement, v.CreatedAt))
            .ToArrayAsync(ct);

        return new AgentSuppressionState(
            projectId,
            suppressions,
            vex.OrderBy(v => v.AdvisoryId, StringComparer.Ordinal).ToArray());
    }

    // ---- Scope --------------------------------------------------------------

    /// <summary>
    /// Why this agent can read nothing, or null if it can.
    ///
    /// The ordinary capability evaluator, at the token's own scope. An agent
    /// holding a role that cannot see evidence is refused here for the same
    /// reason a person holding it would be.
    /// </summary>
    private string? Denied(AgentIdentity agent)
    {
        var decision = _capabilities.Evaluate(agent.Principal, Capability.ViewEvidence);
        return decision.Allowed ? null : decision.Reason;
    }

    /// <summary>
    /// Components under the token's scope. THE scoping rule, in one place.
    ///
    /// Component-scoped: that component alone, never its siblings.
    /// Project-scoped: every component of that project.
    /// Client-scoped: every component under that client.
    /// </summary>
    private IQueryable<Component> Visible(AgentIdentity agent)
    {
        var scope = agent.Scope;
        var query = _db.Components.AsNoTracking();

        if (scope.ComponentId is { } componentId)
            return query.Where(c => c.Id == componentId);

        if (scope.ProjectId is { } projectId)
            return query.Where(c => c.ProjectId == projectId);

        if (scope.ClientId is { } clientId)
            return query.Where(c => c.Project!.ClientId == clientId);

        // No scope is no access, not all access. A token that somehow reached
        // here unscoped reads nothing rather than everything.
        return query.Where(_ => false);
    }

    private async Task<HashSet<Guid>> VisibleIdsAsync(AgentIdentity agent, CancellationToken ct) =>
        (await Visible(agent).Select(c => c.Id).ToArrayAsync(ct)).ToHashSet();

    /// <summary>
    /// Lines around the flagged one, when coverage happened to capture the file.
    ///
    /// This product does not store source for SAST — the only full file content
    /// it holds is what a coverage report brought in. So code context is
    /// available for a flagged file exactly when coverage also ran over it, and
    /// the honest answer the rest of the time is null.
    /// </summary>
    private async Task<AgentCodeContext?> ContextAsync(
        Guid projectId, string filePath, int line, int radius, CancellationToken ct)
    {
        var normalised = filePath.Replace('\\', '/');

        var source = await (
            from f in _db.CoverageSourceFiles.AsNoTracking()
            join r in _db.CoverageReports.AsNoTracking() on f.CoverageReportId equals r.Id
            join cv in _db.ComponentVersions.AsNoTracking() on r.ComponentVersionId equals cv.Id
            join c in _db.Components.AsNoTracking() on cv.ComponentId equals c.Id
            where c.ProjectId == projectId && f.RelativePath == normalised
            orderby cv.CreatedAt descending
            select f.SourceText).FirstOrDefaultAsync(ct);

        if (string.IsNullOrEmpty(source)) return null;

        var lines = source.Replace("\r\n", "\n").Split('\n');
        radius = Math.Clamp(radius, 0, 200);

        var first = Math.Max(1, line - radius);
        var last = Math.Min(lines.Length, line + radius);
        if (first > lines.Length) return null;

        // The starting line number travels with the text. Without it an agent
        // has to guess the offset to quote a line number back, and it will
        // guess wrong on exactly the files where the window was clamped.
        return new AgentCodeContext(first, string.Join('\n', lines[(first - 1)..last]));
    }
}

// ---- Shapes -----------------------------------------------------------------

public sealed record AgentScopeNode(
    string Client, Guid ProjectId, string Project, IReadOnlyList<AgentComponent> Components);

public sealed record AgentComponent(Guid Id, string Name, string? Kind);

public sealed record AgentFindingsFilter(
    Severity? Severity = null, ScannerKind? Scanner = null, string? CommitSha = null,
    string? PathContains = null, int? Limit = null);

public sealed record AgentFinding(
    Guid Id, ScannerKind Scanner, string RuleId, Severity Severity, string Title,
    string? FilePath, int? Line, string? Purl, DateTimeOffset FirstSeen);

/// <summary>
/// Findings plus what was NOT returned. <see cref="Truncated"/> exists so an
/// agent can say "at least 5,000" instead of "200".
/// </summary>
public sealed record AgentFindingsPage(
    IReadOnlyList<AgentFinding> Findings, int Total, bool Truncated, string? Refusal)
{
    public static AgentFindingsPage Empty { get; } = new([], 0, false, null);

    public static AgentFindingsPage Refused(string reason) => new([], 0, false, reason);
}

public sealed record AgentFindingDetail(
    Guid Id, ScannerKind Scanner, string RuleId, Severity Severity, string Title,
    string? Description, string? FilePath, int? Line, string? Snippet, string? Purl,
    string Component, string? CommitSha, string Version,
    DateTimeOffset FirstSeen, DateTimeOffset LastSeen, AgentCodeContext? Context);

public sealed record AgentCodeContext(int FirstLine, string Text);

public sealed record AgentDependencyGraph(
    Guid ComponentId, string? CommitSha, string? Tool, DateTimeOffset CapturedAt,
    IReadOnlyList<AgentPackage> Packages, IReadOnlyList<AgentDependencyEdge> Edges);

public sealed record AgentPackage(
    string Purl, string Name, string Version, string? License, string? Kind,
    string? LatestVersion, IReadOnlyList<string> Advisories);

public sealed record AgentDependencyEdge(string ParentPurl, string ChildPurl);

public sealed record AgentSuppressionState(
    Guid ProjectId,
    IReadOnlyList<AgentSuppression> Suppressions,
    IReadOnlyList<AgentVexStatement> Vex);

public sealed record AgentSuppression(
    Guid Id, SuppressionScope Scope, string? RuleId, string? FilePath, Guid? FindingId,
    string Reason, string Author, ProjectRole AuthorRole,
    DateTimeOffset CreatedAt, DateTimeOffset? ExpiresAt, bool Expired,
    /// <summary>
    /// A pre-TFND-132 row: no tenant recorded, so the matcher still applies it
    /// everywhere and nothing says who wrote it. Reason and author are withheld.
    /// </summary>
    bool InstanceWide);

public sealed record AgentVexStatement(
    string AdvisoryId, string Purl, VexStatementStatus Status, VexJustification? Justification,
    string? ImpactStatement, DateTimeOffset CreatedAt);
