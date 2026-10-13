using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Risk;
using Tamp.Findings.Domain.Risk;
using Tamp.Findings.Domain.Compliance;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Application.Mcp;

/// <summary>
/// Everything an agent can read, and nothing else (TFND-12 / F11.3).
///
/// One class rather than letting the tool layer reach into the ordinary
/// queries, for one reason: every method here starts by resolving the token's
/// scope to a concrete set of project ids and then filters on it. If the tool
/// layer could call <c>FindingsExplorerQuery</c> directly it would be passing a
/// projectId the agent supplied, and the scoping rule would hold only as long
/// as every future tool remembered to check — which is to say, not for long.
///
/// Reads only, and still reads only. The agent surface has grown two narrow
/// writes since — creating a project (TFND-250) and tightening a gate
/// (TFND-252) — and they live in their own services precisely so this sentence
/// stays true of this class. A write path added here would make the comment
/// above it false, and the comment is the thing keeping the scoping argument
/// honest.
///
/// Neither of those writes touches evidence, which is the line that matters: an
/// agent that can file a suppression can retire a finding it was asked to fix,
/// and the whole value of this product is that the evidence is not negotiable.
/// </summary>
public sealed class AgentReadService
{
    private readonly FindingsDbContext _db;
    private readonly AgentScope _scope;
    private readonly GateDecisionService _gates;
    private readonly Projects.ProjectHubQuery _hub;
    private readonly Compliance.ControlDispositionQuery _dispositions;
    private readonly Compliance.ConformanceQuery _conformance;
    private readonly Poam.PoamQuery _poams;
    private readonly CategoryFindingsQuery _categories;
    private readonly Policy.PolicyResolver _policy;
    private readonly EnforcementResolver _enforcement;
    private readonly InstanceEnforcementPolicy _lock;

    // Many dependencies, because "everything an agent can read" is genuinely
    // broad. What used to be the argument for keeping them here — that this is
    // the one place a token's scope is applied — now lives in AgentScope, which
    // the write services share. That is the structure the argument asked for;
    // a private method on one of three services was not.
    public AgentReadService(
        FindingsDbContext db,
        AgentScope scope,
        GateDecisionService gates,
        Projects.ProjectHubQuery hub,
        Compliance.ControlDispositionQuery dispositions,
        Compliance.ConformanceQuery conformance,
        Poam.PoamQuery poams,
        CategoryFindingsQuery categories,
        Policy.PolicyResolver policy,
        EnforcementResolver enforcement,
        InstanceEnforcementPolicy enforcementLock)
    {
        _db = db;
        _scope = scope;
        _gates = gates;
        _hub = hub;
        _dispositions = dispositions;
        _conformance = conformance;
        _poams = poams;
        _categories = categories;
        _policy = policy;
        _enforcement = enforcement;
        _lock = enforcementLock;
    }

    /// <summary>
    /// The projects this identity may see, as the hierarchy the agent should
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
            .Select(p => new { p.Id, ProjectName = p.Name, ClientName = p.Client!.Name })
            .ToArrayAsync(ct);

        return rows
            .Select(r => new AgentScopeNode(r.ClientName, r.Id, r.ProjectName))
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

        var projects = await VisibleIdsAsync(agent, ct);
        if (projects.Count == 0) return AgentFindingsPage.Empty;

        var query =
            from f in _db.Findings.AsNoTracking()
            join cv in _db.ComponentVersions.AsNoTracking() on f.ComponentVersionId equals cv.Id
            where projects.Contains(cv.ProjectId) && f.Status == FindingStatus.Open
            select new { f, cv };

        // One build per project, unless the caller named a commit (TFND-243).
        //
        // Findings are per-build rows and the auto-close sweep only touches the
        // build being ingested, so a finding that survives leaves an Open row
        // behind on every build it ever appeared on. Unscoped, this query
        // returned all of them: a project with six builds and ten persistent
        // findings answered "sixty open findings", repeated the same problem
        // under six different ids, and reported a total the tool description
        // tells the agent to trust.
        //
        // The latest CANONICAL build is the default because it is the build the
        // gate judges — an agent whose finding list and whose verdict described
        // different commits would be reconciling them by hand, wrongly.
        if (filter.CommitSha is not { Length: > 0 })
        {
            var heads = await CanonicalHeadsAsync(projects, ct);

            // A project with no canonical build contributes nothing rather than
            // falling back to a PR build. "Nothing is open on main" is true;
            // "here are findings from an unmerged branch" is a different claim.
            query = query.Where(r => heads.Contains(r.cv.Id));
        }

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

        var picked = await query
            .OrderByDescending(r => r.f.Severity)
            .ThenBy(r => r.f.FilePath)
            .ThenBy(r => r.f.Line)
            .Take(take)
            .Select(r => new
            {
                r.f.Id, r.f.Scanner, r.f.RuleId, r.f.Severity, r.f.Title,
                r.f.FilePath, r.f.Line, r.f.Purl, r.f.FirstSeen, r.f.Hash,
                r.cv.ProjectId,
                Commit = r.cv.CommitSha ?? r.cv.VersionString,
            })
            .ToArrayAsync(ct);

        // The temporal signals (TFND-237), for the page actually returned
        // rather than for the whole project — two bounded queries keyed on the
        // hashes in hand, not a per-row lookup.
        var hashes = picked.Select(r => r.Hash).Distinct().ToArray();
        var projectIds = picked.Select(r => r.ProjectId).Distinct().ToArray();

        // Real age: the earliest any build of the project saw this identity.
        // FirstSeen on the row is only when THIS build saw it, because ingest
        // keys findings per (build, scanner) — so a year-old finding looks
        // newly born on every build it survives.
        var ages = hashes.Length == 0
            ? []
            : await (
                from f in _db.Findings.AsNoTracking()
                join cv in _db.ComponentVersions.AsNoTracking() on f.ComponentVersionId equals cv.Id
                where projectIds.Contains(cv.ProjectId) && hashes.Contains(f.Hash)
                group f by new { cv.ProjectId, f.Hash } into g
                select new { g.Key.ProjectId, g.Key.Hash, Earliest = g.Min(f => f.FirstSeen) })
                .ToArrayAsync(ct);

        var earliest = ages.ToDictionary(a => (a.ProjectId, a.Hash), a => a.Earliest);

        // Attribution: which hashes the PREVIOUS canonical build of each project
        // carried. Present now and absent there means the change under review
        // introduced it.
        var introduced = new Dictionary<Guid, HashSet<string>?>();
        foreach (var projectId in projectIds)
        {
            // Anchored on the commit actually being examined. Asking about a
            // historical commit and attributing against the HEAD's predecessor
            // would compare a build with itself and answer false for every row
            // — a meaningless answer that reads like a real one.
            var examined = picked
                .Where(r => r.ProjectId == projectId)
                .Select(r => r.Commit)
                .FirstOrDefault();

            introduced[projectId] = await PriorBuildHashesAsync(projectId, examined, ct);
        }

        var rows = picked
            .Select(r => new AgentFinding(
                r.Id, r.Scanner, r.RuleId, r.Severity, r.Title,
                r.FilePath, r.Line, r.Purl, r.FirstSeen,
                earliest.TryGetValue((r.ProjectId, r.Hash), out var age) ? age : r.FirstSeen,
                introduced.TryGetValue(r.ProjectId, out var priorHashes) && priorHashes is not null
                    ? !priorHashes.Contains(r.Hash)
                    : null))
            .ToArray();

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

        var projects = await VisibleIdsAsync(agent, ct);

        var row = await (
            from f in _db.Findings.AsNoTracking()
            join cv in _db.ComponentVersions.AsNoTracking() on f.ComponentVersionId equals cv.Id
            where f.Id == findingId && projects.Contains(cv.ProjectId)
            select new
            {
                f.Id, f.Scanner, f.RuleId, f.Severity, f.Title, f.Description,
                f.FilePath, f.Line, f.Snippet, f.Purl, f.FirstSeen, f.LastSeen,
                cv.ProjectId, cv.CommitSha, cv.VersionString,
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
            row.FilePath, row.Line, row.Snippet, row.Purl,
            row.CommitSha, row.VersionString, row.FirstSeen, row.LastSeen, context);
    }

    /// <summary>
    /// The dependency graph for a project's newest SBOM, as flat edges plus
    /// the packages they connect.
    ///
    /// Flat rather than nested: the question an agent asks here is "what pulls
    /// this in", and answering it from a tree means walking the whole tree,
    /// whereas the edge list answers it directly. The caller can nest if it
    /// wants to.
    /// </summary>
    public async Task<AgentDependencyGraph?> DependenciesAsync(
        AgentIdentity agent, Guid projectId, CancellationToken ct = default)
    {
        if (Denied(agent) is not null) return null;

        var projects = await VisibleIdsAsync(agent, ct);
        if (!projects.Contains(projectId)) return null;

        var snapshot = await (
            from s in _db.SbomSnapshots.AsNoTracking()
            join cv in _db.ComponentVersions.AsNoTracking() on s.ComponentVersionId equals cv.Id
            where cv.ProjectId == projectId
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
            projectId, snapshot.CommitSha, snapshot.ToolName, snapshot.CreatedAt, nodes, links);
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

        var projects = await VisibleIdsAsync(agent, ct);
        if (!projects.Contains(projectId)) return null;

        // Anchored in this scope: the caller's own, reason and author included.
        var anchored = await (
            from s in _db.Suppressions.AsNoTracking()
            join f in _db.Findings.AsNoTracking() on s.FindingId equals f.Id
            join cv in _db.ComponentVersions.AsNoTracking() on f.ComponentVersionId equals cv.Id
            where s.FindingId != null && projects.Contains(cv.ProjectId)
            select s).ToArrayAsync(ct);

        // Rule-scoped rows that belong to this project, or to its client.
        var clientId = await _db.Projects.AsNoTracking()
            .Where(p => p.Id == projectId)
            .Select(p => (Guid?)p.ClientId)
            .SingleOrDefaultAsync(ct);

        var ruleScoped = await _db.Suppressions.AsNoTracking()
            .Where(s => s.FindingId == null && s.ClientId != null
                        && s.ClientId == clientId
                        && (s.ProjectId == null || s.ProjectId == projectId))
            .ToArrayAsync(ct);

        // Legacy: written before suppressions carried a tenant. Still applies
        // here, and there is no record of who asked for it.
        var legacy = await _db.Suppressions.AsNoTracking()
            .Where(s => s.FindingId == null && s.ClientId == null)
            .ToArrayAsync(ct);

        var mine = anchored.Concat(ruleScoped).ToArray();

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

    /// <summary>
    /// The release decision for a project's latest canonical build (TFND-236).
    ///
    /// The question an agent sent to remediate something actually has. "What
    /// findings exist" is the question it can already ask, and answering only
    /// that leaves it guessing at which of them stand between this build and a
    /// release — a guess it will make confidently and wrongly, because severity
    /// is not the same thing as a gate.
    ///
    /// Delegates to <see cref="GateDecisionService"/>, the same evaluation the
    /// dashboard and the CLI gate read. Not a second implementation: a gate
    /// verdict that disagreed with the CLI's would be worse than no verdict at
    /// all, because an agent would report it to someone who then ran the CLI.
    /// </summary>
    public async Task<AgentGateDecision?> GateAsync(
        AgentIdentity agent, Guid projectId, CancellationToken ct = default)
    {
        if (Denied(agent) is not null) return null;

        var projects = await VisibleIdsAsync(agent, ct);
        if (!projects.Contains(projectId)) return null;

        var (status, result) = await _gates.ForLatestAsync(projectId, ct);

        // The non-Ok statuses are reported rather than collapsed into a null.
        // "This project has never been built" and "this project is not yours"
        // are different answers, and only one of them means the agent should
        // stop asking.
        if (status != GateDecisionStatus.Ok || result is null)
        {
            return new AgentGateDecision(
                projectId, null, null, null, null,
                Unavailable: status switch
                {
                    GateDecisionStatus.NoBuilds =>
                        "This project has no canonical build yet, so there is nothing to gate. A "
                        + "build on a pull-request branch does not count — gates judge main.",
                    GateDecisionStatus.NoPolicy =>
                        "This instance has no default risk policy seeded, so no verdict can be "
                        + "computed. That is an operator problem, not a remediation one.",
                    GateDecisionStatus.ProjectNotFound =>
                        "That project no longer exists.",
                    _ => "No verdict is available for this project.",
                },
                [], null, null, null, null);
        }

        var gates = result.Evaluation.Results
            .Where(g => g.Enabled)
            .Select(g => new AgentGateRow(
                g.Key, g.Verdict.ToString(), g.Blocks, g.Observed, g.Threshold, g.Reason))
            // Blocking first: the agent is here to clear a gate, and the rows
            // that block are the work. Within that, by verdict then key, so the
            // order is stable across calls rather than whatever the evaluator
            // happened to emit.
            .OrderByDescending(g => g.Blocks)
            .ThenBy(g => g.Verdict, StringComparer.Ordinal)
            .ThenBy(g => g.Key, StringComparer.Ordinal)
            .ToArray();

        return new AgentGateDecision(
            projectId,
            result.Current.CommitSha,
            result.Current.VersionString,
            result.Current.LatestCreatedAt,
            result.Mode.ToString(),
            Unavailable: null,
            gates,
            result.Evaluation.ClearToShip,
            result.Evaluation.Blocking,
            result.CurrentScore,
            result.CurrentBand);
    }

    /// <summary>
    /// The score for the latest canonical build, and where it came from
    /// (TFND-236).
    ///
    /// The breakdown is the point. A bare number invites an agent to invent a
    /// weighting of its own — "criticals are probably most of it" — and then to
    /// prioritise against a model this instance does not use. The per-category
    /// contribution says which work moves the number, which is the only thing
    /// the number is good for.
    ///
    /// Saturated categories are flagged, because they invert the usual advice:
    /// a category at its ceiling cannot get worse, so fixing one more finding
    /// in it moves nothing until the count drops below the clamp.
    /// </summary>
    public async Task<AgentScore?> ScoreAsync(
        AgentIdentity agent, Guid projectId, CancellationToken ct = default)
    {
        if (Denied(agent) is not null) return null;

        var projects = await VisibleIdsAsync(agent, ct);
        if (!projects.Contains(projectId)) return null;

        var (status, result) = await _gates.ForLatestAsync(projectId, ct);
        if (status != GateDecisionStatus.Ok || result is null)
        {
            return new AgentScore(
                projectId, null, null, null, null, null, null, null, [],
                Unavailable: status == GateDecisionStatus.NoBuilds
                    ? "This project has no canonical build yet, so it is unscored. Unscored is not "
                      + "a score of zero and not a clean bill of health."
                    : "No score is available for this project.");
        }

        var risk = result.CurrentRisk;

        // Every category, including the disabled ones, each saying which it is.
        // An agent told only about the enabled ones cannot tell "this project
        // does not score DAST" from "this project scores DAST at zero", and
        // those lead to opposite advice.
        var categories = risk.Breakdown
            .Select(c => new AgentScoreCategory(
                c.Key, c.Enabled, Math.Round(c.EffectiveMax, 1), Math.Round(c.SubScore, 3),
                Math.Round(c.Contribution, 1), c.Saturated))
            .OrderByDescending(c => c.Contribution)
            .ThenBy(c => c.Key, StringComparer.Ordinal)
            .ToArray();

        return new AgentScore(
            projectId,
            result.Current.CommitSha,
            result.Current.VersionString,
            result.CurrentScore,
            result.CurrentBand,
            result.PriorScore,
            result.PriorScore is { } prior ? Math.Round(result.CurrentScore - prior, 1) : null,
            result.PolicyName,
            categories,
            Unavailable: null);
    }

    /// <summary>
    /// The last few canonical builds, scored and gated (TFND-237).
    ///
    /// Priority on this surface is mostly temporal, and a flat list of open
    /// findings carries no time at all. A finding introduced by the commit
    /// under review is a different task from one that has been open for six
    /// months and is already somebody's POA&amp;M item, and an agent cannot tell
    /// them apart from severity.
    ///
    /// Reuses the hub's history rather than scoring builds again here. It is
    /// the expensive read on this surface — six builds means six RiskInputs
    /// builds and six scorer passes — which is why the hub caps it at six and
    /// why this does not offer a way to ask for more.
    /// </summary>
    public async Task<AgentBuildHistory?> BuildsAsync(
        AgentIdentity agent, Guid projectId, CancellationToken ct = default)
    {
        if (Denied(agent) is not null) return null;

        var projects = await VisibleIdsAsync(agent, ct);
        if (!projects.Contains(projectId)) return null;

        var project = await _db.Projects.AsNoTracking()
            .Where(p => p.Id == projectId)
            .Select(p => new Projects.ProjectRef(
                p.ClientId, p.Client!.Name, p.Id, p.Name, p.RiskPolicyId, p.GatesConfig))
            .SingleOrDefaultAsync(ct);
        if (project is null) return null;

        var hub = await _hub.LoadAsync(project, commitSha: null, ct);
        if (hub is null)
        {
            return new AgentBuildHistory(projectId, [], Unavailable:
                "This project has no canonical build yet, so there is no history. A project "
                + "registered but never scanned is this state, and it is not a healthy one.");
        }

        // No canonical filter here any more: TFND-244 moved it into the hub, so
        // hub.History is canonical by construction and matches the gate. A
        // second filter would be a second definition of "the build", which is
        // the defect that ticket was.
        var builds = hub.History
            .Select(b => new AgentBuild(
                b.CommitSha, b.Branch, b.VersionString, b.IngestedAt,
                Math.Round(b.Score, 1),
                b.Delta is { } d ? Math.Round(d, 1) : null,
                b.CoveragePercent is { } cov ? Math.Round(cov, 1) : null,
                b.Gates.ClearToShip, b.Gates.Blocking, b.Gates.Enabled))
            .ToArray();

        return new AgentBuildHistory(projectId, builds, Unavailable: null);
    }

    /// <summary>
    /// The finding identities carried by the canonical build immediately BEFORE
    /// the one being examined, or null when there is no such build (TFND-237).
    ///
    /// Anchored on the examined commit rather than always on the head's
    /// predecessor. Asking about a historical commit and diffing it against the
    /// head's predecessor would, for that commit, compare a build with itself
    /// and report every finding as not-introduced — a meaningless answer in the
    /// shape of a real one.
    ///
    /// "Canonical" is defined the same way the gate defines it — main or master,
    /// no pull-request ref — because an agent comparing against a different set
    /// of builds than the gate judges would attribute findings to the wrong
    /// change. If that definition moves, both move together or the drift is a
    /// bug.
    ///
    /// Null rather than an empty set when there is no earlier build. Empty would
    /// say "the previous build had no findings", which reads as every finding
    /// being newly introduced — the wrong answer, asserted confidently, on
    /// exactly the project where nobody has history to check it against.
    /// </summary>
    private async Task<HashSet<string>?> PriorBuildHashesAsync(
        Guid projectId, string? examinedCommit, CancellationToken ct)
    {
        var commits = await _db.ComponentVersions.AsNoTracking()
            .Where(v => v.ProjectId == projectId
                     && v.PullRequestRef == null
                     && (v.BranchName == null || v.BranchName == "main" || v.BranchName == "master"))
            .GroupBy(v => v.CommitSha ?? v.VersionString)
            .Select(g => new { Commit = g.Key, Latest = g.Max(v => v.CreatedAt) })
            .OrderByDescending(g => g.Latest)
            .ToArrayAsync(ct);

        // The examined commit may not be canonical at all — a caller can name a
        // pull-request build. There is no "the build before" a branch build, so
        // attribution is refused rather than answered against main's history.
        var at = examinedCommit is null
            ? 0
            : Array.FindIndex(commits, c => c.Commit == examinedCommit);
        if (at < 0) return null;

        if (at + 1 >= commits.Length) return null;

        var prior = commits[at + 1].Commit;

        var hashes = await (
            from f in _db.Findings.AsNoTracking()
            join cv in _db.ComponentVersions.AsNoTracking() on f.ComponentVersionId equals cv.Id
            where cv.ProjectId == projectId && (cv.CommitSha ?? cv.VersionString) == prior
            select f.Hash).Distinct().ToArrayAsync(ct);

        return hashes.ToHashSet(StringComparer.Ordinal);
    }

    /// <summary>
    /// The build ids making up each project's latest canonical commit
    /// (TFND-243).
    ///
    /// A commit can produce several builds — one per flavor (net10, web,
    /// deployed) — and they are one build of one commit as far as any reader is
    /// concerned, so all of a commit's ids come back together. Scoring and
    /// gating treat a commit as the unit for the same reason.
    ///
    /// "Canonical" is main or master with no pull-request ref, matching
    /// <see cref="GateDecisionService"/>. Projects with no canonical build at
    /// all contribute no ids, which reads downstream as "nothing open on main"
    /// rather than as findings from an unmerged branch.
    /// </summary>
    private async Task<HashSet<Guid>> CanonicalHeadsAsync(
        IReadOnlyCollection<Guid> projectIds, CancellationToken ct)
    {
        var rows = await _db.ComponentVersions.AsNoTracking()
            .Where(v => projectIds.Contains(v.ProjectId)
                     && v.PullRequestRef == null
                     && (v.BranchName == null || v.BranchName == "main" || v.BranchName == "master"))
            .Select(v => new
            {
                v.Id,
                v.ProjectId,
                Commit = v.CommitSha ?? v.VersionString,
                v.CreatedAt,
            })
            .ToArrayAsync(ct);

        var heads = new HashSet<Guid>();

        foreach (var perProject in rows.GroupBy(r => r.ProjectId))
        {
            var head = perProject
                .GroupBy(r => r.Commit)
                .Select(g => new { Commit = g.Key, Latest = g.Max(r => r.CreatedAt) })
                .OrderByDescending(g => g.Latest)
                .FirstOrDefault();

            if (head is null) continue;

            foreach (var row in perProject.Where(r => r.Commit == head.Commit))
                heads.Add(row.Id);
        }

        return heads;
    }

    /// <summary>
    /// Which controls this project owns, inherits, or has ruled out, and which
    /// are still unmapped (TFND-238).
    ///
    /// The surface where an agent is most likely to assert something false if
    /// it cannot read the real answer. A disposition is an AUTHORED human
    /// position — the project is the authority (ADR 0015) and the justification
    /// points at code — not a fact derived from the findings, and an agent that
    /// inferred one from the evidence it can see would be inventing a
    /// compliance claim.
    ///
    /// Capped, and the unmapped controls are never the ones cut. A baseline runs
    /// to several hundred controls; the ones with no assertion are the gap the
    /// no-unmapped meta-gate blocks on, so they are the rows worth a reader's
    /// attention and they sort first.
    /// </summary>
    public async Task<AgentControlCoverage?> ControlsAsync(
        AgentIdentity agent, Guid projectId, ControlDisposition? only, int? limit,
        CancellationToken ct = default)
    {
        if (Denied(agent) is not null) return null;

        var projects = await VisibleIdsAsync(agent, ct);
        if (!projects.Contains(projectId)) return null;

        // Build-independent (capability: null), because an agent asking what a
        // project owns is asking about the project, not about whether the last
        // build happened to be able to produce the evidence. Passing a build's
        // capability here would turn a Gated control into N/A on the strength of
        // one build's shape, which is a different question than the one asked.
        var coverage = await _dispositions.ForProjectAsync(projectId, capability: null, ct);

        if (coverage is null)
        {
            return new AgentControlCoverage(
                projectId, 0, 0, 0, 0, 0, false, [], 0,
                Unavailable:
                "This project has no compliance framework assigned, or the instance has no current "
                + "control catalog, so there are no controls to disposition. That is a setup state, "
                + "not a finding — and it is not the same as having nothing to prove.");
        }

        var rows = coverage.Controls.AsEnumerable();
        if (only is { } wanted) rows = rows.Where(c => c.Disposition == wanted);

        var matching = rows
            // Unmapped first: it is the gap, and a cap that cut it would hide
            // exactly what the reader needs.
            .OrderByDescending(c => c.Disposition == ControlDisposition.Unmapped)
            .ThenBy(c => c.Family, StringComparer.Ordinal)
            .ThenBy(c => c.ControlId, StringComparer.Ordinal)
            .ToArray();

        var take = Math.Clamp(limit ?? 100, 1, 500);

        var controls = matching
            .Take(take)
            .Select(c => new AgentControl(
                c.ControlId, c.Title, c.Family, c.Disposition.ToString(), c.Detail, c.Source,
                c.Overridden))
            .ToArray();

        return new AgentControlCoverage(
            projectId, coverage.InScope, coverage.Gated, coverage.Inherited,
            coverage.NotApplicable, coverage.Unmapped, coverage.Complete,
            controls, matching.Length, Unavailable: null);
    }

    /// <summary>
    /// Open POA&amp;M items, and the findings they cover (TFND-238).
    ///
    /// The answer to "why is this still open". A finding on a POA&amp;M has an
    /// owner, a scheduled date and somebody's plan attached; proposing a fix for
    /// it is not wrong, but presenting it as unaddressed is. Past-due items are
    /// marked, because a plan whose date has passed is a different state from a
    /// plan in progress and the remedy is somebody's attention rather than code.
    /// </summary>
    public async Task<AgentPoamBoard?> PoamsAsync(
        AgentIdentity agent, Guid projectId, DateTimeOffset asOf, CancellationToken ct = default)
    {
        if (Denied(agent) is not null) return null;

        var projects = await VisibleIdsAsync(agent, ct);
        if (!projects.Contains(projectId)) return null;

        var board = await _poams.BoardAsync(projectId, asOf, ct);

        var items = board.Items
            .Select(i => new AgentPoamItem(
                i.Id, i.Title, i.WeaknessDescription, i.Severity, i.Status.ToString(),
                i.Owner, i.ScheduledCompletionDate, i.CreatedAt, i.ClosedAt, i.PastDue,
                i.LinkCount, i.ControlIds))
            .ToArray();

        return new AgentPoamBoard(
            projectId, items,
            board.Stats.Open, board.Stats.InProgress, board.Stats.Completed,
            board.Stats.RiskAccepted, board.Stats.PastDue, board.Stats.Unscheduled);
    }

    /// <summary>
    /// ADR-conformance verdicts for the latest build (TFND-238).
    ///
    /// A second finding pipeline — claims checked against the project's own
    /// architecture decisions (ADR 0012) rather than rules a scanner shipped —
    /// and the one an agent most needs to read before changing structural code,
    /// because the thing it is about to do may be the thing an ADR forbids.
    ///
    /// Dispositioned verdicts are included and marked. A Fail somebody has
    /// already accepted with a justification is settled, and re-raising it is
    /// the same mistake as re-raising a suppressed finding.
    /// </summary>
    public async Task<AgentConformance?> ConformanceAsync(
        AgentIdentity agent, Guid projectId, CancellationToken ct = default)
    {
        if (Denied(agent) is not null) return null;

        var projects = await VisibleIdsAsync(agent, ct);
        if (!projects.Contains(projectId)) return null;

        var report = await _conformance.ForProjectAsync(projectId, commitSha: null, ct);

        if (report is null)
        {
            return new AgentConformance(
                projectId, null, null, 0, 0, 0, 0, 0, [],
                Unavailable:
                "No ADR-conformance run has been ingested for this project. Absence of verdicts is "
                + "not conformance — nothing has been checked.");
        }

        var findings = report.Findings
            .Select(f => new AgentConformanceFinding(
                f.AdrRef, f.RuleId, f.Claim, f.Verdict.ToString(), f.Method.ToString(),
                f.CodeEvidence, f.Location, f.ControlRefs, f.Blocks,
                f.Dispositioned, f.DispositionJustification))
            // Blocking first, then undispositioned: the work, then the record.
            .OrderByDescending(f => f.Blocks)
            .ThenBy(f => f.Dispositioned)
            .ThenBy(f => f.AdrRef, StringComparer.Ordinal)
            .ToArray();

        return new AgentConformance(
            projectId, report.CommitSha, report.EvaluatedAt,
            report.Pass, report.Fail, report.Unknown, report.Error, report.Dispositioned,
            findings, Unavailable: null);
    }

    /// <summary>
    /// Tests and coverage for the latest canonical build (TFND-239).
    ///
    /// What an agent should read before it changes code: whether the area it is
    /// about to touch is tested at all, and whether the build it is working from
    /// was green. A fix shipped into a red build is indistinguishable, in the
    /// next report, from the thing that was already broken.
    ///
    /// Coverage here is the build-level roll-up. Per-file coverage is not
    /// surfaced: it exists only for files a coverage report happened to include,
    /// and a partial map presented as a map is worse than none.
    /// </summary>
    public async Task<AgentQuality?> QualityAsync(
        AgentIdentity agent, Guid projectId, CancellationToken ct = default)
    {
        if (Denied(agent) is not null) return null;

        var projects = await VisibleIdsAsync(agent, ct);
        if (!projects.Contains(projectId)) return null;

        var heads = await CanonicalHeadsAsync([projectId], ct);
        if (heads.Count == 0)
        {
            return new AgentQuality(projectId, null, null, null,
                Unavailable: "This project has no canonical build, so there is nothing to report.");
        }

        var commit = await _db.ComponentVersions.AsNoTracking()
            .Where(v => heads.Contains(v.Id))
            .Select(v => v.CommitSha)
            .FirstOrDefaultAsync(ct);

        var tests = await _db.TestRunReports.AsNoTracking()
            .Where(t => heads.Contains(t.ComponentVersionId))
            .OrderByDescending(t => t.IngestedAt)
            .Select(t => new AgentTestRun(
                t.ToolName, t.TotalCount, t.PassedCount, t.FailedCount, t.SkippedCount,
                t.InconclusiveCount, t.CompletedAt))
            .FirstOrDefaultAsync(ct);

        var coverage = await _db.CoverageReports.AsNoTracking()
            .Where(c => heads.Contains(c.ComponentVersionId))
            .OrderByDescending(c => c.IngestedAt)
            .Select(c => new AgentCoverage(
                c.ToolName, c.SequenceCoverage, c.BranchCoverage,
                c.CoveredSequences, c.TotalSequences, c.IngestedAt))
            .FirstOrDefaultAsync(ct);

        return new AgentQuality(projectId, commit, tests, coverage,
            // Said rather than left as two nulls. "No tests ran" and "tests ran
            // and passed" are opposite facts, and an absent report is the first.
            Unavailable: tests is null && coverage is null
                ? "Neither a test report nor a coverage report was ingested for this build. That is "
                  + "not a passing build — it is an unmeasured one."
                : null);
    }

    /// <summary>
    /// Packages whose license nobody could classify (TFND-239).
    ///
    /// Instance-wide work, surfaced per project because the project is what the
    /// agent has a scope for. A license is a global FACT about a package
    /// (ADR 0017) — attesting to one is a human act, but gathering the evidence
    /// for it is exactly the legwork an agent is good at, and the unresolved
    /// list is where that legwork starts.
    ///
    /// Deliberately only the unknowns. The resolved map is this instance's
    /// position on hundreds of packages and an agent does not need to read it to
    /// do the one thing it can usefully do here.
    /// </summary>
    public async Task<AgentLicenseWorklist?> LicenseWorklistAsync(
        AgentIdentity agent, Guid projectId, CancellationToken ct = default)
    {
        if (Denied(agent) is not null) return null;

        var projects = await VisibleIdsAsync(agent, ct);
        if (!projects.Contains(projectId)) return null;

        var overview = await _categories.LicenseOverviewAsync(projectId, commitSha: null, ct);

        if (overview is null)
        {
            return new AgentLicenseWorklist(projectId, [], 0, 0, 0,
                Unavailable: "This project has no SBOM, so there are no package licenses to classify.");
        }

        var unknowns = overview.Unknowns
            .Select(u => new AgentUnresolvedLicense(u.Purl, u.Name, u.Version, u.DeclaredLicense))
            .OrderBy(u => u.Purl, StringComparer.Ordinal)
            .ToArray();

        return new AgentLicenseWorklist(
            projectId, unknowns, overview.TotalComponents, overview.DeniedCount,
            overview.ResolvedApplied, Unavailable: null);
    }

    /// <summary>
    /// Repository and organisation posture observations (TFND-239 / TFND-212).
    ///
    /// Control evidence that is not a scanner result: branch protection, whether
    /// reviews are required, signed commits, org 2FA. An agent cannot remediate
    /// most of it — these are settings a person changes — so the value is in not
    /// proposing code for a control that is failing because of a checkbox.
    ///
    /// Reports its own absence clearly, because the producer is upstream work
    /// (TAM-290) and "nothing observed" will be the normal answer until it ships.
    /// An unobserved check is not a passing check.
    /// </summary>
    public async Task<AgentPosture?> PostureAsync(
        AgentIdentity agent, Guid projectId, CancellationToken ct = default)
    {
        if (Denied(agent) is not null) return null;

        var projects = await VisibleIdsAsync(agent, ct);
        if (!projects.Contains(projectId)) return null;

        // One row per check, enforced by a unique index on (ProjectId, CheckId):
        // an observation is upserted, so this table holds current state and not
        // a history. Worth stating, because the obvious defensive thing here —
        // group by check and take the latest — would be dead code implying a
        // history that does not exist.
        var latest = await _db.PostureObservations.AsNoTracking()
            .Where(o => o.ProjectId == projectId)
            .OrderBy(o => o.CheckId)
            .Select(o => new AgentPostureCheck(
                o.CheckId, o.Status.ToString(), o.Detail, o.Source, o.ObservedAt))
            .ToArrayAsync(ct);

        return new AgentPosture(projectId, latest,
            Unavailable: latest.Length == 0
                ? "No posture observation has been reported for this project. The producer that "
                  + "reports branch protection, review requirements and org 2FA is upstream work, "
                  + "so this is the expected answer for now — and an unobserved check is not a "
                  + "passing one."
                : null);
    }

    // ---- Scope --------------------------------------------------------------

    /// <summary>
    /// The policy in force for a project, and which layer imposed each part of
    /// it (TFND-251).
    ///
    /// Unconditional: reading a policy reveals no evidence and changes nothing,
    /// and an agent that cannot read the policy cannot explain a verdict it is
    /// already allowed to see.
    ///
    /// Provenance is the point. ADR 0007 carries the imposing layer through the
    /// merge, and "this threshold is the template's, you cannot loosen it here"
    /// is the sentence that stops an agent proposing an impossible edit — or
    /// reporting a successful one after a write the merge discarded.
    ///
    /// Reports the enforcement lock too, because that decides whether the edit
    /// tools work at all. An agent that can read the lock does not have to
    /// discover it by failing.
    /// </summary>
    public async Task<AgentPolicy?> PolicyAsync(
        AgentIdentity agent, Guid projectId, CancellationToken ct = default)
    {
        if (Denied(agent) is not null) return null;
        if (!await _scope.ReachesAsync(agent, projectId, ct)) return null;

        var own = await _db.Projects.AsNoTracking()
            .Where(p => p.Id == projectId)
            .Select(p => p.GatesConfig)
            .SingleOrDefaultAsync(ct);

        var merged = await _policy.ForProjectAsync(projectId, ct);
        var effectiveMode = await _enforcement.ForProjectAsync(projectId, ct);

        // Every well-known gate, including the ones nothing turns on. An agent
        // told only about the enabled gates cannot tell "this instance does not
        // gate on DAST" from "DAST passes", and those lead to opposite advice.
        var gates = GateEvaluator.WellKnownGateKeys
            .Select(key =>
            {
                merged.Gates.TryGetValue(key, out var winner);

                // Declared with an initializer because the null-conditional
                // below may not run, and an out parameter on a call that never
                // happens is not assigned.
                GateConfig? projectValue = null;
                own?.Gates.TryGetValue(key, out projectValue);

                return new AgentPolicyGate(
                    key,
                    GateEvaluator.Label(key),
                    GateEvaluator.Describe(key),
                    winner?.Enabled ?? false,
                    winner?.Threshold,
                    Policy.GateService.TakesThreshold(key),
                    // Null when no layer sets it at all — nothing imposed it, so
                    // naming a source would invent one.
                    winner is null ? null : winner.Source,
                    projectValue?.Enabled,
                    projectValue?.Threshold);
            })
            .OrderByDescending(g => g.Enabled)
            .ThenBy(g => g.Key, StringComparer.Ordinal)
            .ToArray();

        return new AgentPolicy(
            projectId,
            gates,
            effectiveMode.ToString(),
            own?.EnforcementMode?.ToString(),
            merged.Mode is { } m ? m.Source : null,
            _lock.ConfigLocked,
            merged.RequiredScanners.Select(s => new AgentSourcedValue(s.Value, s.Source)).ToArray(),
            merged.DeniedLicenses.Select(d => new AgentSourcedValue(d.Value, d.Source)).ToArray(),
            merged.PoamDeadlineDays
                .Select(kv => new AgentPoamDeadline(kv.Key, kv.Value.Value, kv.Value.Source))
                .OrderBy(d => d.Severity, StringComparer.Ordinal)
                .ToArray());
    }

    // The scoping rule moved to AgentScope at TFND-251, when reads stopped being
    // the only thing an agent can do. These two stay as delegations so the
    // call sites below are unchanged — the rule is shared, not copied.
    private string? Denied(AgentIdentity agent) => _scope.DeniedRead(agent);

    private IQueryable<Project> Visible(AgentIdentity agent) => _scope.Visible(agent);

    private Task<HashSet<Guid>> VisibleIdsAsync(AgentIdentity agent, CancellationToken ct) =>
        _scope.VisibleIdsAsync(agent, ct);

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
            where cv.ProjectId == projectId && f.RelativePath == normalised
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

public sealed record AgentScopeNode(string Client, Guid ProjectId, string Project);

public sealed record AgentFindingsFilter(
    Severity? Severity = null, ScannerKind? Scanner = null, string? CommitSha = null,
    string? PathContains = null, int? Limit = null);

public sealed record AgentFinding(
    Guid Id, ScannerKind Scanner, string RuleId, Severity Severity, string Title,
    string? FilePath, int? Line, string? Purl,
    /// <summary>
    /// When THIS BUILD first saw it, which is not the finding's age (TFND-237).
    ///
    /// Ingest keys findings per (build, scanner), so a finding that has been
    /// present for a year gets a fresh row — and a fresh FirstSeen — on every
    /// build it survives. Reporting this as "open since" is wrong, and wrong in
    /// the direction that makes old problems look new.
    ///
    /// Use <see cref="FirstSeenInProject"/> for age, and
    /// <see cref="IntroducedInThisBuild"/> for "did this change cause it".
    /// </summary>
    DateTimeOffset FirstSeen,
    /// <summary>
    /// The earliest this finding's identity was seen anywhere in the project —
    /// its real age. Computed across builds by hash (TFND-237).
    /// </summary>
    DateTimeOffset FirstSeenInProject,
    /// <summary>
    /// Absent from the previous canonical build, present in this one: the
    /// change under review introduced it (TFND-237).
    ///
    /// Null, not false, when there is no previous canonical build to compare
    /// against. On a project's first build everything is new in one sense and
    /// nothing is attributable in the sense that matters, and false would be a
    /// claim this surface cannot support.
    /// </summary>
    bool? IntroducedInThisBuild);

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
    string? CommitSha, string Version,
    DateTimeOffset FirstSeen, DateTimeOffset LastSeen, AgentCodeContext? Context);

public sealed record AgentCodeContext(int FirstLine, string Text);

/// <summary>
/// The release decision for a build (TFND-236).
///
/// Carries the verdict AND the build it belongs to. A verdict without the
/// commit that produced it is the one shape an agent can most easily misreport:
/// it will have changed the code since, and "the gate passes" said about a
/// build that no longer reflects the tree is a false statement with this
/// product's name on it.
/// </summary>
public sealed record AgentGateDecision(
    Guid ProjectId,
    string? CommitSha,
    string? VersionString,
    DateTimeOffset? BuiltAt,
    /// <summary>"Advisory" or "Enforcing" — whether a blocking gate actually stops a release.</summary>
    string? EnforcementMode,
    /// <summary>Why there is no verdict, when there is none. Null when the rest is populated.</summary>
    string? Unavailable,
    IReadOnlyList<AgentGateRow> Gates,
    bool? ClearToShip,
    int? Blocking,
    double? Score,
    string? Band);

/// <summary>
/// One gate's verdict. <see cref="Observed"/> and <see cref="Reason"/> are the
/// evaluator's own strings, passed through verbatim — the same text the CLI
/// gate prints, so an agent and the pipeline cannot describe one failure two
/// ways.
/// </summary>
public sealed record AgentGateRow(
    string Key,
    /// <summary>Pass, Fail, Unknown, Error or NotApplicable (ADR 0001's four-valued verdict, plus N/A).</summary>
    string Verdict,
    bool Blocks,
    string Observed,
    double? Threshold,
    string? Reason);

/// <summary>
/// The score, and what produced it (TFND-236).
/// </summary>
public sealed record AgentScore(
    Guid ProjectId,
    string? CommitSha,
    string? VersionString,
    double? Score,
    string? Band,
    double? PriorScore,
    /// <summary>Points moved since the previous canonical build. Positive is worse.</summary>
    double? DeltaPoints,
    /// <summary>The scoring policy this came from, so an agent names it rather than implying a universal scale.</summary>
    string? PolicyName,
    IReadOnlyList<AgentScoreCategory> Categories,
    string? Unavailable);

/// <summary>
/// One category's share of the score.
/// </summary>
public sealed record AgentScoreCategory(
    string Key,
    bool Enabled,
    /// <summary>Points this category can cost at full saturation under this policy.</summary>
    double EffectiveMax,
    /// <summary>0..1 — how far toward its ceiling this category is.</summary>
    double SubScore,
    /// <summary>Points it is actually costing. This is the number that says where the work is.</summary>
    double Contribution,
    /// <summary>
    /// At its ceiling: more findings of this class cannot raise the score, and
    /// fixing one cannot lower it until the count drops below the clamp.
    /// </summary>
    bool Saturated);

/// <summary>
/// Recent canonical builds, newest first (TFND-237).
/// </summary>
public sealed record AgentBuildHistory(
    Guid ProjectId,
    IReadOnlyList<AgentBuild> Builds,
    string? Unavailable);

public sealed record AgentBuild(
    string CommitSha,
    string? Branch,
    string VersionString,
    DateTimeOffset IngestedAt,
    double Score,
    /// <summary>Points moved against the build before it. Null on the oldest row shown.</summary>
    double? DeltaPoints,
    double? CoveragePercent,
    bool ClearToShip,
    int Blocking,
    int GatesEnabled);

public sealed record AgentDependencyGraph(
    Guid ProjectId, string? CommitSha, string? Tool, DateTimeOffset CapturedAt,
    IReadOnlyList<AgentPackage> Packages, IReadOnlyList<AgentDependencyEdge> Edges);

public sealed record AgentPackage(
    string Purl, string Name, string Version, string? License, string? Kind,
    string? LatestVersion, IReadOnlyList<string> Advisories);

public sealed record AgentDependencyEdge(string ParentPurl, string ChildPurl);

// ---- Compliance (TFND-238) --------------------------------------------------

/// <summary>
/// A project's control dispositions and the roll-up over them (TFND-238).
/// </summary>
public sealed record AgentControlCoverage(
    Guid ProjectId,
    int InScope,
    int Gated,
    int Inherited,
    int NotApplicable,
    /// <summary>Controls with no assertion at all — the gap the no-unmapped meta-gate blocks on.</summary>
    int Unmapped,
    /// <summary>Every in-scope control has a disposition.</summary>
    bool Complete,
    IReadOnlyList<AgentControl> Controls,
    /// <summary>How many matched the filter, which may exceed what was returned.</summary>
    int Matching,
    string? Unavailable);

/// <summary>
/// One control's disposition.
///
/// <see cref="Detail"/> is the gate labels for a Gated control, or the
/// inheritance/N-A justification otherwise — which is where the code reference
/// backing the claim lives (ADR 0015). <see cref="Source"/> names the policy
/// layer that supplied the winning assertion.
/// </summary>
public sealed record AgentControl(
    string ControlId,
    string Title,
    string Family,
    /// <summary>Gated, Inherited, NotApplicable or Unmapped.</summary>
    string Disposition,
    string? Detail,
    string? Source,
    /// <summary>
    /// True when this disposition is a reviewed DOWNGRADE of a stricter baseline
    /// default (ADR 0015 §5), approved by someone holding AcceptRisk. An agent must
    /// not read it as an ordinary claim: somebody decided the control is weaker here
    /// than the baseline says, so it is a deliberate, audited exception rather than
    /// evidence the control is covered.
    /// </summary>
    bool Overridden = false);

/// <summary>
/// Open plans of action and milestones, with the roll-up (TFND-238).
/// </summary>
public sealed record AgentPoamBoard(
    Guid ProjectId,
    IReadOnlyList<AgentPoamItem> Items,
    int Open,
    int InProgress,
    int Completed,
    int RiskAccepted,
    int PastDue,
    /// <summary>Items with no scheduled completion date — a plan without a date.</summary>
    int Unscheduled);

public sealed record AgentPoamItem(
    Guid Id,
    string Title,
    string WeaknessDescription,
    Severity Severity,
    string Status,
    /// <summary>
    /// The display name of the person who FILED the item, which is what the
    /// board calls the owner. There is no separate assignee field, so this is
    /// who to ask about it rather than necessarily who is doing it.
    /// </summary>
    string Owner,
    DateTimeOffset? ScheduledCompletionDate,
    DateTimeOffset CreatedAt,
    DateTimeOffset? ClosedAt,
    bool PastDue,
    /// <summary>How many findings this item covers.</summary>
    int LinkedFindings,
    /// <summary>
    /// The 800-53 controls this weakness is in, in the catalog's display form
    /// (TFND-180). The reason an agent can ask "what is outstanding against SC-7"
    /// and get an answer, instead of grepping weakness prose for a control number.
    /// </summary>
    IReadOnlyList<string> ControlIds);

/// <summary>
/// ADR-conformance verdicts for a build (TFND-238 / ADR 0012).
/// </summary>
public sealed record AgentConformance(
    Guid ProjectId,
    string? CommitSha,
    DateTimeOffset? EvaluatedAt,
    int Pass,
    int Fail,
    int Unknown,
    int Error,
    /// <summary>Verdicts somebody has accepted with a justification — settled, not open.</summary>
    int Dispositioned,
    IReadOnlyList<AgentConformanceFinding> Findings,
    string? Unavailable);

public sealed record AgentConformanceFinding(
    string AdrRef,
    string RuleId,
    string Claim,
    /// <summary>Pass, Fail, Unknown or Error.</summary>
    string Verdict,
    /// <summary>Deterministic (a rule) or Semantic (a model read the ADR).</summary>
    string Method,
    string? CodeEvidence,
    string? Location,
    IReadOnlyList<string> ControlRefs,
    bool Blocks,
    bool Dispositioned,
    string? DispositionJustification);

// ---- Quality and supply chain (TFND-239) ------------------------------------

/// <summary>
/// Tests and coverage for a build (TFND-239).
/// </summary>
public sealed record AgentQuality(
    Guid ProjectId,
    string? CommitSha,
    AgentTestRun? Tests,
    AgentCoverage? Coverage,
    string? Unavailable);

public sealed record AgentTestRun(
    string Tool,
    int Total,
    int Passed,
    int Failed,
    int Skipped,
    int Inconclusive,
    DateTimeOffset CompletedAt);

public sealed record AgentCoverage(
    string Tool,
    double SequencePercent,
    double BranchPercent,
    int CoveredSequences,
    int TotalSequences,
    DateTimeOffset IngestedAt);

/// <summary>
/// Packages whose license nobody could classify (TFND-239 / ADR 0017).
/// </summary>
public sealed record AgentLicenseWorklist(
    Guid ProjectId,
    IReadOnlyList<AgentUnresolvedLicense> Unresolved,
    int TotalComponents,
    /// <summary>Packages whose license this project's policy denies outright.</summary>
    int DeniedCount,
    /// <summary>How many packages the knowledge base already resolved for this build.</summary>
    int ResolvedApplied,
    string? Unavailable);

public sealed record AgentUnresolvedLicense(
    string Purl,
    string Name,
    string Version,
    /// <summary>What the SBOM declared, when it declared something unparseable rather than nothing.</summary>
    string? DeclaredLicense);

/// <summary>
/// Repository and organisation posture (TFND-239 / TFND-212).
/// </summary>
public sealed record AgentPosture(
    Guid ProjectId,
    IReadOnlyList<AgentPostureCheck> Checks,
    string? Unavailable);

public sealed record AgentPostureCheck(
    string CheckId,
    string Status,
    string? Detail,
    /// <summary>What reported it, so a reader can tell an observation from an assumption.</summary>
    string? Source,
    DateTimeOffset ObservedAt);

// ---- Policy (TFND-251) ------------------------------------------------------

/// <summary>
/// The policy in force for a project, with per-value provenance (TFND-251).
/// </summary>
public sealed record AgentPolicy(
    Guid ProjectId,
    IReadOnlyList<AgentPolicyGate> Gates,
    /// <summary>The mode a verdict is actually judged under, after the whole chain resolves.</summary>
    string EffectiveEnforcementMode,
    /// <summary>This project's own override, or null when it inherits.</summary>
    string? ProjectEnforcementOverride,
    /// <summary>Which layer supplied the strictest mode across the merge.</summary>
    string? EnforcementSource,
    /// <summary>
    /// The deployment pins enforcement by configuration. While true, policy
    /// EDIT tooling is closed — reads are not.
    /// </summary>
    bool EnforcementLocked,
    IReadOnlyList<AgentSourcedValue> RequiredScanners,
    IReadOnlyList<AgentSourcedValue> DeniedLicenses,
    IReadOnlyList<AgentPoamDeadline> PoamDeadlines);

/// <summary>
/// One gate's effective configuration, and what this project itself asked for.
///
/// The two are reported separately on purpose. Where an upper layer is stricter,
/// the merge discards the project's value — so an agent comparing
/// <see cref="ProjectEnabled"/> against <see cref="Enabled"/> can see that its
/// own layer is not what is in force, instead of assuming a write took effect.
/// </summary>
public sealed record AgentPolicyGate(
    string Key,
    string Label,
    string Description,
    bool Enabled,
    double? Threshold,
    /// <summary>False for a boolean gate, where a threshold is meaningless.</summary>
    bool HasThreshold,
    /// <summary>
    /// The layer that imposed the winning value — a template, a client, the
    /// archetype, or this project. Null when no layer sets this gate at all.
    /// </summary>
    string? Source,
    /// <summary>What this project's own layer says, or null when it says nothing.</summary>
    bool? ProjectEnabled,
    double? ProjectThreshold);

public sealed record AgentSourcedValue(string Value, string Source);

public sealed record AgentPoamDeadline(string Severity, int Days, string Source);

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
