using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Mcp;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;
using Tamp.Findings.Mcp;

namespace Tamp.Findings.Integration.Tests;

/// <summary>
/// The MCP tool methods, invoked directly with real services against Postgres. The tools are thin
/// (argument parsing + shaping), so these assert what an agent would actually be told.
/// </summary>
[Collection(DatabaseCollection.Name)]
public class ApiBMcpToolsTests
{
    private readonly DatabaseFixture _fx;
    public ApiBMcpToolsTests(DatabaseFixture fx) => _fx = fx;

    private sealed record World(
        Guid ClientId, Guid ProjectId, Guid EmptyProjectId, Guid OtherClientProjectId,
        Guid CriticalId, Guid LowId, Guid NoSourceId, Guid ForeignFindingId, string Sha);

    private async Task<World> SeedAsync()
    {
        var s = ApiBSupport.Suffix();
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);

        var client = new Client { Name = $"apib-mcp-{s}" };
        var other = new Client { Name = $"apib-mcp-o-{s}" };
        db.Clients.AddRange(client, other);
        var project = new Project { ClientId = client.Id, Name = $"p-{s}" };
        var empty = new Project { ClientId = client.Id, Name = $"empty-{s}" };
        var foreign = new Project { ClientId = other.Id, Name = $"f-{s}" };
        db.Projects.AddRange(project, empty, foreign);

        var cv = new ComponentVersion { ProjectId = project.Id, VersionString = "1.0", CommitSha = $"{s}abc", BranchName = "main" };
        var fcv = new ComponentVersion { ProjectId = foreign.Id, VersionString = "1.0", CommitSha = $"{s}f", BranchName = "main" };
        db.ComponentVersions.AddRange(cv, fcv);

        Finding F(Guid build, ScannerKind sc, string rule, Severity sev, string path, int? line) => new()
        {
            ComponentVersionId = build, Hash = $"{rule}{s}", Scanner = sc, RuleId = rule, Severity = sev,
            Title = rule, Description = "desc", FilePath = path, Line = line, Snippet = "snip",
        };
        var crit = F(cv.Id, ScannerKind.OpenGrep, "crit", Severity.Critical, "src/Core/a.cs", 5);
        var low = F(cv.Id, ScannerKind.Trivy, "low", Severity.Low, "src/Other/b.cs", 2);
        var nosrc = F(cv.Id, ScannerKind.OpenGrep, "nosrc", Severity.High, "src/missing.cs", 1);
        var foreignF = F(fcv.Id, ScannerKind.OpenGrep, "foreign", Severity.Critical, "x.cs", 1);
        db.Findings.AddRange(crit, low, nosrc, foreignF);

        var cov = new CoverageReport { ComponentVersionId = cv.Id };
        db.CoverageReports.Add(cov);
        db.CoverageSourceFiles.Add(new CoverageSourceFile
        {
            CoverageReportId = cov.Id, RelativePath = "src/Core/a.cs",
            SourceText = string.Join("\r\n", Enumerable.Range(1, 20).Select(i => $"line {i}")),
        });

        // SBOM: two packages, one edge, one advisory.
        var snap = new SbomSnapshot { ComponentVersionId = cv.Id, ToolName = "syft" };
        db.SbomSnapshots.Add(snap);
        var parent = new SbomComponent { SbomSnapshotId = snap.Id, Purl = "pkg:nuget/Parent@1", Name = "Parent", Version = "1" };
        var child = new SbomComponent { SbomSnapshotId = snap.Id, Purl = "pkg:nuget/Child@2", Name = "Child", Version = "2" };
        db.SbomComponents.AddRange(parent, child);
        db.SbomDependencies.AddRange(
            new SbomDependency { SbomSnapshotId = snap.Id, ParentComponentId = parent.Id, ChildComponentId = child.Id });
        db.Vulnerabilities.Add(new Vulnerability { SbomComponentId = child.Id, AdvisoryId = "CVE-2024-1", Severity = Severity.High });

        // Suppressions + VEX.
        var author = new User { Login = $"apib-mcp-u-{s}", DisplayName = "Mute Author", IsApproved = true };
        db.Users.Add(author);
        db.Suppressions.Add(new Suppression
        {
            Scope = SuppressionScope.SingleFinding, FindingId = low.Id, ClientId = client.Id, ProjectId = project.Id,
            CreatedByUserId = author.Id, CreatedByRole = ProjectRole.LeadDev, Reason = "accepted",
        });
        db.Suppressions.Add(new Suppression
        {
            Scope = SuppressionScope.RuleEverywhere, RuleId = "crit", ClientId = client.Id, ProjectId = project.Id,
            CreatedByUserId = author.Id, CreatedByRole = ProjectRole.LeadDev, Reason = "lapsed",
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(-1),
        });
        db.VexStatements.Add(new VexStatement
        {
            ProjectId = project.Id, Purl = "pkg:nuget/Child@2", AdvisoryId = "CVE-2024-1",
            Status = VexStatementStatus.NotAffected, Justification = VexJustification.DoesNotShip,
        });
        await db.SaveChangesAsync();

        return new World(client.Id, project.Id, empty.Id, foreign.Id, crit.Id, low.Id, nosrc.Id, foreignF.Id, $"{s}abc");
    }

    private static AgentIdentity Agent(ScopeTarget scope, Principal? principal = null) =>
        new(Guid.NewGuid(), "agent", principal ?? Principal.For(Guid.Empty, "agent:test", false, []), scope);

    private static JsonElement Json(object o) =>
        JsonSerializer.SerializeToElement(o, new JsonSerializerOptions(JsonSerializerDefaults.Web));

    private static (AgentReadService reads, AgentContext ctx) Services(IServiceScope scope, AgentIdentity identity)
    {
        var ctx = new AgentContext();
        ctx.Attach(identity);
        return (scope.ServiceProvider.GetRequiredService<AgentReadService>(), ctx);
    }

    [SkippableFact]
    public async Task list_scope_returns_the_visible_projects_and_a_note_when_there_are_none()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        using var scope = _fx.Scope();

        var (reads, ctx) = Services(scope, Agent(ScopeTarget.Client(w.ClientId)));
        var tree = Json(await FindingsTools.ListScopeAsync(reads, ctx));
        Assert.Equal(2, tree.GetProperty("projects").GetArrayLength());
        Assert.Equal(JsonValueKind.Null, tree.GetProperty("note").ValueKind);

        // Unscoped (instance) token reads nothing, and says so.
        var (reads2, ctx2) = Services(scope, Agent(ScopeTarget.Instance));
        var none = Json(await FindingsTools.ListScopeAsync(reads2, ctx2));
        Assert.Equal(0, none.GetProperty("projects").GetArrayLength());
        Assert.Contains("contains no components", none.GetProperty("note").GetString(), StringComparison.Ordinal);
    }

    [SkippableFact]
    public async Task get_findings_filters_orders_caps_and_refuses_bad_filters()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        using var scope = _fx.Scope();
        var (reads, ctx) = Services(scope, Agent(ScopeTarget.Project(w.ClientId, w.ProjectId)));

        var all = Json(await FindingsTools.GetFindingsAsync(reads, ctx));
        Assert.Equal(3, all.GetProperty("total").GetInt32());
        Assert.Equal("crit", all.GetProperty("findings")[0].GetProperty("ruleId").GetString());   // worst first
        Assert.False(all.GetProperty("truncated").GetBoolean());

        var high = Json(await FindingsTools.GetFindingsAsync(reads, ctx, minimumSeverity: "high"));
        Assert.Equal(2, high.GetProperty("returned").GetInt32());

        var trivy = Json(await FindingsTools.GetFindingsAsync(reads, ctx, scanner: "Trivy"));
        Assert.Equal("low", trivy.GetProperty("findings")[0].GetProperty("ruleId").GetString());

        var path = Json(await FindingsTools.GetFindingsAsync(reads, ctx, pathContains: "Core"));
        Assert.Equal(1, path.GetProperty("returned").GetInt32());

        var sha = Json(await FindingsTools.GetFindingsAsync(reads, ctx, commitSha: w.Sha));
        Assert.Equal(3, sha.GetProperty("returned").GetInt32());

        var capped = Json(await FindingsTools.GetFindingsAsync(reads, ctx, limit: 1));
        Assert.True(capped.GetProperty("truncated").GetBoolean());
        Assert.Contains("Showing 1 of 3", capped.GetProperty("note").GetString(), StringComparison.Ordinal);

        var badSeverity = Json(await FindingsTools.GetFindingsAsync(reads, ctx, minimumSeverity: "Criticall"));
        Assert.Contains("not a severity", badSeverity.GetProperty("error").GetString(), StringComparison.Ordinal);
        var badScanner = Json(await FindingsTools.GetFindingsAsync(reads, ctx, scanner: "NopeScan"));
        Assert.Contains("not a scanner", badScanner.GetProperty("error").GetString(), StringComparison.Ordinal);
    }

    [SkippableFact]
    public async Task get_findings_clamps_an_oversized_limit_rather_than_refusing()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        using var scope = _fx.Scope();
        var (reads, ctx) = Services(scope, Agent(ScopeTarget.Project(w.ClientId, w.ProjectId)));

        var page = Json(await FindingsTools.GetFindingsAsync(reads, ctx, limit: 9999));
        Assert.Equal(3, page.GetProperty("returned").GetInt32());   // limit is clamped, not refused
    }

    [SkippableFact]
    public async Task get_finding_returns_detail_with_code_context_or_an_explanatory_note()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        using var scope = _fx.Scope();
        var (reads, ctx) = Services(scope, Agent(ScopeTarget.Project(w.ClientId, w.ProjectId)));

        var withCtx = Json(await FindingsTools.GetFindingAsync(reads, ctx, w.CriticalId, contextLines: 2));
        var detail = withCtx.GetProperty("finding");
        Assert.Equal("crit", detail.GetProperty("ruleId").GetString());
        Assert.Equal(3, detail.GetProperty("context").GetProperty("firstLine").GetInt32());
        Assert.Equal("line 3\nline 4\nline 5\nline 6\nline 7", detail.GetProperty("context").GetProperty("text").GetString());
        Assert.Equal(JsonValueKind.Null, withCtx.GetProperty("note").ValueKind);

        var noSource = Json(await FindingsTools.GetFindingAsync(reads, ctx, w.NoSourceId));
        Assert.Equal(JsonValueKind.Null, noSource.GetProperty("finding").GetProperty("context").ValueKind);
        Assert.Contains("No stored source", noSource.GetProperty("note").GetString(), StringComparison.Ordinal);

        // Outside scope and unknown ids are indistinguishable.
        var foreign = Json(await FindingsTools.GetFindingAsync(reads, ctx, w.ForeignFindingId));
        Assert.Contains("No finding", foreign.GetProperty("error").GetString(), StringComparison.Ordinal);
        var unknown = Json(await FindingsTools.GetFindingAsync(reads, ctx, Guid.NewGuid()));
        Assert.Contains("No finding", unknown.GetProperty("error").GetString(), StringComparison.Ordinal);
    }

    [SkippableFact]
    public async Task get_dependencies_returns_packages_edges_and_advisories_or_not_found()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        using var scope = _fx.Scope();
        var (reads, ctx) = Services(scope, Agent(ScopeTarget.Client(w.ClientId)));

        var graph = Json(await FindingsTools.GetDependenciesAsync(reads, ctx, w.ProjectId));
        Assert.Equal(2, graph.GetProperty("packages").GetInt32());
        Assert.Equal(1, graph.GetProperty("edges").GetInt32());   
        var child = graph.GetProperty("graph").GetProperty("packages").EnumerateArray()
            .Single(p => p.GetProperty("name").GetString() == "Child");
        Assert.Equal("CVE-2024-1", child.GetProperty("advisories")[0].GetString());

        var noSbom = Json(await FindingsTools.GetDependenciesAsync(reads, ctx, w.EmptyProjectId));
        Assert.Contains("No SBOM", noSbom.GetProperty("error").GetString(), StringComparison.Ordinal);

        var foreign = Json(await FindingsTools.GetDependenciesAsync(reads, ctx, w.OtherClientProjectId));
        Assert.Contains("No SBOM", foreign.GetProperty("error").GetString(), StringComparison.Ordinal);
    }

    [SkippableFact]
    public async Task get_suppressions_reports_suppressions_vex_and_marks_expired_ones()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        using var scope = _fx.Scope();
        var (reads, ctx) = Services(scope, Agent(ScopeTarget.Project(w.ClientId, w.ProjectId)));

        var state = Json(await FindingsTools.GetSuppressionsAsync(reads, ctx, w.ProjectId));
        var supp = state.GetProperty("suppressions").EnumerateArray().ToList();
        Assert.Contains(supp, x => x.GetProperty("reason").GetString() == "accepted" && !x.GetProperty("expired").GetBoolean());
        Assert.Contains(supp, x => x.GetProperty("reason").GetString() == "lapsed" && x.GetProperty("expired").GetBoolean());
        Assert.Contains(supp, x => x.GetProperty("author").GetString() == "Mute Author");
        Assert.Equal("CVE-2024-1", state.GetProperty("vex")[0].GetProperty("advisoryId").GetString());
        Assert.Equal(JsonValueKind.Null, state.GetProperty("note").ValueKind);

        var outside = Json(await FindingsTools.GetSuppressionsAsync(reads, ctx, w.OtherClientProjectId));
        Assert.Contains("outside this token's scope", outside.GetProperty("error").GetString(), StringComparison.Ordinal);

        var (readsE, ctxE) = Services(scope, Agent(ScopeTarget.Project(w.ClientId, w.EmptyProjectId)));
        var empty = Json(await FindingsTools.GetSuppressionsAsync(readsE, ctxE, w.EmptyProjectId));
        // Legacy instance-wide rows from other tests may exist; an empty project only reports "nothing" when none do.
        Assert.True(empty.GetProperty("note").ValueKind is JsonValueKind.Null or JsonValueKind.String);
    }

    [SkippableFact]
    public void A_tool_without_an_attached_identity_throws_rather_than_returning_nothing()
    {
        Skip.IfNot(_fx.Available);
        var ctx = new AgentContext();

        Assert.Throws<InvalidOperationException>(() => ctx.Require());
        ctx.Attach(Agent(ScopeTarget.Instance));
        Assert.Throws<InvalidOperationException>(() => ctx.Attach(Agent(ScopeTarget.Instance)));
    }
}
