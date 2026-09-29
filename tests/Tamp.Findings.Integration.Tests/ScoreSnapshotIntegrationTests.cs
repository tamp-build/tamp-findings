using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Api.Contracts;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Ingest;
using Tamp.Findings.Application.Projects;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Integration.Tests;

// Per-build score snapshots (TFND-176). Ingest freezes a build's score; the portfolio trend reads
// it back instead of re-scoring, and only reuses a snapshot computed under the current policy.
[Collection(DatabaseCollection.Name)]
public class ScoreSnapshotIntegrationTests
{
    private readonly DatabaseFixture _fx;
    public ScoreSnapshotIntegrationTests(DatabaseFixture fx) => _fx = fx;

    // A project with two canonical (main, non-PR) builds. Returns the project + each build's
    // (cvId, commitSha), oldest first.
    private async Task<(Guid ProjectId, string ProjectName, (Guid Cv, string Sha)[] Builds)> SeedTwoBuildsAsync()
    {
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var s = Guid.NewGuid().ToString("N")[..8];
        var client = new Client { Name = $"ss-{s}" };
        db.Clients.Add(client);
        var project = new Project { ClientId = client.Id, Name = $"ssp-{s}" };
        db.Projects.Add(project);
        var comp = new Component { ProjectId = project.Id, Name = "svc" };
        db.Components.Add(comp);
        var now = DateTimeOffset.UtcNow;
        var v1 = new ComponentVersion { ProjectId = comp.ProjectId, ComponentId = comp.Id, VersionString = "0.1.0", CommitSha = $"{s}old", BranchName = "main", CreatedAt = now.AddDays(-1) };
        var v2 = new ComponentVersion { ProjectId = comp.ProjectId, ComponentId = comp.Id, VersionString = "0.2.0", CommitSha = $"{s}new", BranchName = "main", CreatedAt = now };
        db.ComponentVersions.AddRange(v1, v2);
        // A finding on the newer build so the two builds don't score identically.
        db.Findings.Add(new Finding
        {
            ComponentVersionId = v2.Id, Hash = $"h{s}", Scanner = ScannerKind.OpenGrep, RuleId = "r1",
            Severity = Severity.Critical, Title = "boom", FirstSeen = now, LastSeen = now, Status = FindingStatus.Open,
        });
        await db.SaveChangesAsync();
        return (project.Id, project.Name, [(v1.Id, v1.CommitSha!), (v2.Id, v2.CommitSha!)]);
    }

    [SkippableFact]
    public async Task RecordForBuild_writes_a_snapshot_with_score_and_policy()
    {
        Skip.IfNot(_fx.Available);
        var (projectId, _, builds) = await SeedTwoBuildsAsync();

        using (var scope = _fx.Scope())
        {
            var svc = scope.ServiceProvider.GetRequiredService<ScoreSnapshotService>();
            await svc.RecordForBuildAsync(builds[1].Cv);
        }

        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            var snap = await db.ScoreSnapshots.SingleAsync(x => x.ProjectId == projectId && x.CommitSha == builds[1].Sha);
            Assert.NotEqual("", snap.PolicyName);
            Assert.NotEmpty(snap.Breakdown);          // per-category contributions captured
            Assert.True(snap.Score >= 0);
        }
    }

    [SkippableFact]
    public async Task Portfolio_trend_reads_the_snapshot_scores()
    {
        Skip.IfNot(_fx.Available);
        var (projectId, projectName, builds) = await SeedTwoBuildsAsync();

        double s0, s1;
        using (var scope = _fx.Scope())
        {
            var svc = scope.ServiceProvider.GetRequiredService<ScoreSnapshotService>();
            await svc.RecordForBuildAsync(builds[0].Cv);
            await svc.RecordForBuildAsync(builds[1].Cv);
            var db = _fx.Db(scope);
            s0 = (await db.ScoreSnapshots.SingleAsync(x => x.CommitSha == builds[0].Sha)).Score;
            s1 = (await db.ScoreSnapshots.SingleAsync(x => x.CommitSha == builds[1].Sha)).Score;
        }

        using (var scope = _fx.Scope())
        {
            var portfolio = scope.ServiceProvider.GetRequiredService<PortfolioQuery>();
            var row = (await portfolio.LoadAsync(VisibleSet.Everything)).Single(r => r.ProjectName == projectName);
            // Oldest-first, straight from the snapshots.
            Assert.Equal(new[] { s0, s1 }, row.Trend);
        }
    }

    [SkippableFact]
    public async Task A_snapshot_from_a_different_policy_is_ignored_and_recomputed()
    {
        Skip.IfNot(_fx.Available);
        var (projectId, projectName, builds) = await SeedTwoBuildsAsync();

        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            // A poisoned snapshot under a policy that isn't the project's current one.
            db.ScoreSnapshots.Add(new ScoreSnapshot
            {
                ProjectId = projectId, CommitSha = builds[0].Sha, Score = 999, PolicyName = "Some Other Policy",
                BuiltAt = DateTimeOffset.UtcNow.AddDays(-1), ComputedAt = DateTimeOffset.UtcNow,
            });
            await db.SaveChangesAsync();
        }

        using (var scope = _fx.Scope())
        {
            var portfolio = scope.ServiceProvider.GetRequiredService<PortfolioQuery>();
            var row = (await portfolio.LoadAsync(VisibleSet.Everything)).Single(r => r.ProjectName == projectName);
            Assert.Equal(2, row.Trend.Count);
            Assert.DoesNotContain(999d, row.Trend);   // wrong-policy snapshot never leaks into the trend
        }
    }

    [SkippableFact]
    public async Task Findings_ingest_writes_a_snapshot_for_the_build()
    {
        Skip.IfNot(_fx.Available);
        var s = Guid.NewGuid().ToString("N")[..8];
        Guid projectId, userId; string clientName, projectNm;
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            var user = new User { Login = $"si-{s}", DisplayName = "si", Email = $"si{s}@e.test", IsApproved = true };
            db.Users.Add(user);
            var client = new Client { Name = $"si-{s}" };
            db.Clients.Add(client);
            var project = new Project { ClientId = client.Id, Name = $"sip-{s}" };
            db.Projects.Add(project);
            await db.SaveChangesAsync();
            (projectId, userId, clientName, projectNm) = (project.Id, user.Id, client.Name, project.Name);
        }

        string token;
        using (var scope = _fx.Scope())
            token = (await scope.ServiceProvider.GetRequiredService<IngestTokenService>()
                .MintProjectTokenAsync(projectId, "si-tok", userId, default)).Plaintext;

        var http = _fx.Factory!.CreateClient();
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        var sha = $"{s}deadbeef";
        var req = new IngestRequest(clientName, projectNm, "svc", null, null, "1.0.0", sha, "main", null, null,
            ScannerKind.OpenGrep,
            [new IngestFinding("r1", Severity.High, "x", null, "a.cs", 3, null, null)]);

        var resp = await http.PostAsJsonAsync("/ingest/findings", req);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            Assert.True(await db.ScoreSnapshots.AnyAsync(x => x.ProjectId == projectId && x.CommitSha == sha),
                "the findings ingest should have frozen a score snapshot for the build");
        }
    }
}
