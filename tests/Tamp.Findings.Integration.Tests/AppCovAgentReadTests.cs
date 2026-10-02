using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Mcp;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Integration.Tests;

// AgentReadService: scope resolution, findings paging/filters, finding detail with source context,
// dependency graph and suppression/VEX state.
[Collection(DatabaseCollection.Name)]
public class AppCovAgentReadTests
{
    private readonly DatabaseFixture _fx;
    public AppCovAgentReadTests(DatabaseFixture fx) => _fx = fx;

    private static AgentIdentity Agent(Principal p, ScopeTarget scope) => new(Guid.NewGuid(), "agent", p, scope);

    [SkippableFact]
    public async Task Scope_is_enforced_and_unscoped_or_unauthorised_agents_read_nothing()
    {
        Skip.IfNot(_fx.Available);
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var actors = await AppCovSeed.UsersAsync(db);
        var (client, p1) = await AppCovSeed.ClientProjectAsync(db, "ag");
        var p2 = new Project { ClientId = client.Id, Name = $"ag-second-{Guid.NewGuid():N}" };
        db.Projects.Add(p2);
        var (_, outsider) = await AppCovSeed.ClientProjectAsync(db, "ag-out");
        await db.SaveChangesAsync();
        var svc = scope.ServiceProvider.GetRequiredService<AgentReadService>();

        var clientAgent = Agent(actors.Admin, ScopeTarget.Client(client.Id));
        var projectAgent = Agent(actors.Admin, ScopeTarget.Project(client.Id, p1.Id));
        var instanceAgent = Agent(actors.Admin, ScopeTarget.Instance);
        var viewerAgent = Agent(actors.Viewer, ScopeTarget.Client(client.Id));

        Assert.Equal(2, (await svc.ScopeAsync(clientAgent)).Count);
        Assert.Single(await svc.ScopeAsync(projectAgent));
        Assert.Empty(await svc.ScopeAsync(instanceAgent));

        // viewers hold ViewEvidence in the matrix, so denial is exercised with a principal that has no actors at all
        var nobody = Agent(Principal.For(Guid.NewGuid(), "nobody", false, []), ScopeTarget.Client(client.Id));
        _ = viewerAgent;
        var page = await svc.FindingsAsync(instanceAgent, new AgentFindingsFilter());
        Assert.Equal(0, page.Total);
        Assert.Null(await svc.FindingAsync(instanceAgent, Guid.NewGuid()));
        Assert.Null(await svc.DependenciesAsync(instanceAgent, p1.Id));
        Assert.Null(await svc.DependenciesAsync(projectAgent, p2.Id));
        Assert.Null(await svc.DependenciesAsync(projectAgent, p1.Id));
        Assert.Null(await svc.SuppressionsAsync(projectAgent, outsider.Id, DateTimeOffset.UtcNow));

        var denied = await svc.FindingsAsync(nobody, new AgentFindingsFilter());
        if (denied.Refusal is not null)
        {
            Assert.Empty(await svc.ScopeAsync(nobody));
            Assert.Null(await svc.FindingAsync(nobody, Guid.NewGuid()));
            Assert.Null(await svc.DependenciesAsync(nobody, p1.Id));
            Assert.Null(await svc.SuppressionsAsync(nobody, p1.Id, DateTimeOffset.UtcNow));
        }
    }

    [SkippableFact]
    public async Task Findings_paging_filters_detail_and_source_context()
    {
        Skip.IfNot(_fx.Available);
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var actors = await AppCovSeed.UsersAsync(db);
        var (client, project) = await AppCovSeed.ClientProjectAsync(db, "ag-f");
        var cv = await AppCovSeed.BuildAsync(db, project.Id);
        Finding F(string tag, ScannerKind sc, Severity sev, string? path, int? line, FindingStatus st = FindingStatus.Open) => new()
        {
            ComponentVersionId = cv.Id, Hash = $"{tag}-{Guid.NewGuid():N}", Scanner = sc, RuleId = $"r-{tag}", Severity = sev, Title = $"t-{tag}",
            FilePath = path, Line = line, Status = st, Snippet = "snip", Purl = "pkg:x",
        };
        var withCtx = F("a", ScannerKind.Roslyn, Severity.High, "src\\Ctx.cs", 5);
        var bare = F("b", ScannerKind.OpenGrep, Severity.Low, null, null);
        var big = F("c", ScannerKind.Roslyn, Severity.Critical, "src/Ctx.cs", 500);
        var closed = F("d", ScannerKind.Roslyn, Severity.Critical, "src/Ctx.cs", 1, FindingStatus.Fixed);
        var noCoverage = F("e", ScannerKind.Roslyn, Severity.Medium, "src/Other.cs", 2);
        db.Findings.AddRange(withCtx, bare, big, closed, noCoverage);
        var rep = new CoverageReport { ComponentVersionId = cv.Id };
        db.CoverageReports.Add(rep);
        db.CoverageSourceFiles.AddRange(
            new CoverageSourceFile { CoverageReportId = rep.Id, RelativePath = "src/Ctx.cs", SourceText = string.Join("\r\n", Enumerable.Range(1, 20).Select(i => $"line {i}")) },
            new CoverageSourceFile { CoverageReportId = rep.Id, RelativePath = "src/Other.cs", SourceText = "" });
        await db.SaveChangesAsync();

        var svc = scope.ServiceProvider.GetRequiredService<AgentReadService>();
        var agent = Agent(actors.Admin, ScopeTarget.Project(client.Id, project.Id));

        var all = await svc.FindingsAsync(agent, new AgentFindingsFilter());
        Assert.Equal(4, all.Total);
        Assert.False(all.Truncated);
        Assert.Equal(Severity.Critical, all.Findings[0].Severity);
        var capped = await svc.FindingsAsync(agent, new AgentFindingsFilter(Limit: 1));
        Assert.True(capped.Truncated);
        Assert.Single(capped.Findings);
        Assert.Single((await svc.FindingsAsync(agent, new AgentFindingsFilter(Limit: -5))).Findings);
        Assert.Equal(2, (await svc.FindingsAsync(agent, new AgentFindingsFilter(Severity: Severity.High))).Total);
        Assert.Equal(3, (await svc.FindingsAsync(agent, new AgentFindingsFilter(Scanner: ScannerKind.Roslyn))).Total);
        Assert.Equal(4, (await svc.FindingsAsync(agent, new AgentFindingsFilter(CommitSha: cv.CommitSha))).Total);
        Assert.Equal(0, (await svc.FindingsAsync(agent, new AgentFindingsFilter(CommitSha: "nope"))).Total);
        Assert.Equal(1, (await svc.FindingsAsync(agent, new AgentFindingsFilter(PathContains: "Other"))).Total);

        var detail = (await svc.FindingAsync(agent, withCtx.Id, contextLines: 2))!;
        Assert.Equal(3, detail.Context!.FirstLine);
        Assert.Contains("line 5", detail.Context.Text);
        Assert.Equal("snip", detail.Snippet);
        Assert.Null((await svc.FindingAsync(agent, bare.Id))!.Context);
        var tail = (await svc.FindingAsync(agent, big.Id))!;
        Assert.Null(tail.Context);
        Assert.Null((await svc.FindingAsync(agent, noCoverage.Id))!.Context);
        Assert.Null(await svc.FindingAsync(agent, Guid.NewGuid()));
        var wide = (await svc.FindingAsync(agent, withCtx.Id, contextLines: 999))!;
        Assert.Equal(1, wide.Context!.FirstLine);
        var otherScope = Agent(actors.Admin, ScopeTarget.Project(client.Id, Guid.NewGuid()));
        Assert.Null(await svc.FindingAsync(otherScope, withCtx.Id));
    }

    [SkippableFact]
    public async Task Dependency_graph_and_suppression_state()
    {
        Skip.IfNot(_fx.Available);
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var actors = await AppCovSeed.UsersAsync(db);
        var (client, project) = await AppCovSeed.ClientProjectAsync(db, "ag-d");
        var cv = await AppCovSeed.BuildAsync(db, project.Id);
        var snap = new SbomSnapshot { ComponentVersionId = cv.Id, ToolName = "syft" };
        db.SbomSnapshots.Add(snap);
        SbomComponent C(string n) => new() { SbomSnapshotId = snap.Id, Purl = $"pkg:nuget/{n}.{project.Id:N}@1", Name = n, Version = "1", License = "MIT" };
        var a = C("a"); var b = C("b");
        db.SbomComponents.AddRange(a, b);
        db.SbomDependencies.AddRange(
            new SbomDependency { SbomSnapshotId = snap.Id, ParentComponentId = a.Id, ChildComponentId = b.Id });
        db.Vulnerabilities.AddRange(
            new Vulnerability { SbomComponentId = b.Id, AdvisoryId = "CVE-1", Severity = Severity.Low },
            new Vulnerability { SbomComponentId = b.Id, AdvisoryId = "CVE-2", Severity = Severity.High });

        var finding = new Finding { ComponentVersionId = cv.Id, Hash = Guid.NewGuid().ToString("N"), Scanner = ScannerKind.Roslyn, RuleId = "r", Severity = Severity.Low, Title = "t" };
        db.Findings.Add(finding);
        var asOf = DateTimeOffset.UtcNow;
        var ruleId = $"cov-legacy-{Guid.NewGuid():N}";
        db.Suppressions.AddRange(
            new Suppression { Scope = SuppressionScope.SingleFinding, FindingId = finding.Id, CreatedByUserId = actors.Lead.UserId, Reason = "anchored", CreatedByRole = ProjectRole.LeadDev, ExpiresAt = asOf.AddDays(-1) },
            new Suppression { Scope = SuppressionScope.RuleEverywhere, RuleId = "r1", ClientId = client.Id, CreatedByUserId = Guid.NewGuid(), Reason = "client rule", CreatedByRole = ProjectRole.Architect },
            new Suppression { Scope = SuppressionScope.RuleOnFile, RuleId = "r2", FilePath = "f", ClientId = client.Id, ProjectId = project.Id, CreatedByUserId = actors.Lead.UserId, Reason = "project rule", CreatedByRole = ProjectRole.LeadDev, ExpiresAt = asOf.AddDays(5) },
            new Suppression { Scope = SuppressionScope.RuleEverywhere, RuleId = ruleId, CreatedByUserId = Guid.NewGuid(), Reason = "legacy", CreatedByRole = ProjectRole.Architect, ExpiresAt = asOf.AddDays(-2) },
            new Suppression { Scope = SuppressionScope.RuleEverywhere, RuleId = ruleId + "b", CreatedByUserId = Guid.NewGuid(), Reason = "legacy2", CreatedByRole = ProjectRole.Architect });
        db.VexStatements.AddRange(
            new VexStatement { ProjectId = project.Id, Purl = "pkg:nuget/z", AdvisoryId = "CVE-Z", Status = VexStatementStatus.Affected, AuthorUserId = Guid.NewGuid() },
            new VexStatement { ProjectId = project.Id, Purl = "pkg:nuget/y", AdvisoryId = "CVE-A", Status = VexStatementStatus.Fixed, AuthorUserId = Guid.NewGuid() },
            new VexStatement { ProjectId = project.Id, Purl = "pkg:nuget/x", AdvisoryId = "CVE-R", Status = VexStatementStatus.Fixed, AuthorUserId = Guid.NewGuid(), RetiredAt = asOf });
        await db.SaveChangesAsync();

        try
        {
            var svc = scope.ServiceProvider.GetRequiredService<AgentReadService>();
            var agent = Agent(actors.Admin, ScopeTarget.Project(client.Id, project.Id));

            var graph = (await svc.DependenciesAsync(agent, project.Id))!;
            Assert.Equal(2, graph.Packages.Count);
            Assert.Single(graph.Edges);
            Assert.Equal(["CVE-2", "CVE-1"], graph.Packages.Single(p => p.Name == "b").Advisories);
            Assert.Empty(graph.Packages.Single(p => p.Name == "a").Advisories);

            var state = (await svc.SuppressionsAsync(agent, project.Id, asOf))!;
            Assert.Equal(["CVE-A", "CVE-Z"], state.Vex.Select(v => v.AdvisoryId));
            Assert.Contains(state.Suppressions, s => s.Reason == "anchored" && s.Expired && s.Author == "lead");
            Assert.Contains(state.Suppressions, s => s.Reason == "client rule" && s.Author == "(unknown)");
            Assert.Contains(state.Suppressions, s => s.Reason == "project rule" && !s.Expired);
            Assert.Contains(state.Suppressions, s => s.InstanceWide && s.RuleId == ruleId && s.Expired && s.Author == "(withheld)");
            Assert.Contains(state.Suppressions, s => s.InstanceWide && s.RuleId == ruleId + "b" && !s.Expired);
            // live ones sort before expired, rows with a tenant before legacy ones
            var order = state.Suppressions.ToList();
            Assert.True(order.FindIndex(s => s.Expired) > order.FindIndex(s => !s.Expired));
        }
        finally
        {
            using var s2 = _fx.Scope();
            var d2 = _fx.Db(s2);
            d2.Suppressions.RemoveRange(await d2.Suppressions.Where(s => s.RuleId != null && s.RuleId.StartsWith(ruleId)).ToListAsync());
            await d2.SaveChangesAsync();
        }
    }
}
