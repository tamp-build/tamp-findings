using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Ingest;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Integration.Tests;

// TFND-264: build identity is the COMMIT. The version string is a fallback that may only adopt a build whose
// commit is not yet known — it must never pull a different commit's evidence into an existing build. Before
// the fix, a producer with a fixed product version (Strata's StrataVersion) collapsed every nightly into the
// first night's build, kept the first sha, and replace-on-ingest overwrote the earlier commit's evidence.
[Collection(DatabaseCollection.Name)]
public class BuildIdentityIntegrationTests
{
    private readonly DatabaseFixture _fx;
    public BuildIdentityIntegrationTests(DatabaseFixture fx) => _fx = fx;

    private sealed record World(Guid ProjectId, string ClientName, string ProjectName, HttpClient Http);

    private async Task<World> SeedAsync()
    {
        var s = Guid.NewGuid().ToString("N")[..8];
        Guid projectId, userId; string clientName, projectName;
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            var user = new User { Login = $"bid-{s}", DisplayName = "b", Email = $"b{s}@e.test", IsApproved = true };
            var client = new Client { Name = $"bid-c-{s}" };
            var project = new Project { ClientId = client.Id, Name = $"bid-p-{s}" };
            db.Users.Add(user); db.Clients.Add(client); db.Projects.Add(project);
            await db.SaveChangesAsync();
            (projectId, userId, clientName, projectName) = (project.Id, user.Id, client.Name, project.Name);
        }
        string token;
        using (var scope = _fx.Scope())
            token = (await scope.ServiceProvider.GetRequiredService<IngestTokenService>()
                .MintProjectTokenAsync(projectId, "bid", userId, default)).Plaintext;
        var http = _fx.Factory!.CreateClient();
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return new World(projectId, clientName, projectName, http);
    }

    private static string Sha(char c) => new(c, 40);

    // The quality-gate ingest is the smallest replace-on-ingest evidence: one verdict per build.
    private static async Task<Guid> PostGateAsync(World w, string version, string? sha, string status,
        string? flavor = null, string? pr = null)
    {
        var resp = await w.Http.PostAsJsonAsync("/ingest/quality-gate", new
        {
            client = w.ClientName, project = w.ProjectName, flavor, version, commitSha = sha,
            pullRequestRef = pr, status, source = "test",
        });
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var body = await resp.Content.ReadFromJsonAsync<System.Text.Json.JsonElement>();
        return body.GetProperty("componentVersionId").GetGuid();
    }

    private async Task<List<ComponentVersion>> BuildsAsync(Guid projectId)
    {
        using var scope = _fx.Scope();
        return await _fx.Db(scope).ComponentVersions.AsNoTracking().Where(v => v.ProjectId == projectId).ToListAsync();
    }

    private async Task<string?> GateStatusAsync(Guid buildId)
    {
        using var scope = _fx.Scope();
        return (await _fx.Db(scope).QualityGateResults.AsNoTracking().FirstOrDefaultAsync(r => r.ComponentVersionId == buildId))?.Status;
    }

    [SkippableTheory]
    [InlineData(null)]
    [InlineData("linux")]   // flavored: the old (project, flavor, version) unique index would have rejected the second build
    public async Task Two_commits_with_the_same_version_string_are_two_builds_and_neither_overwrites_the_other(string? flavor)
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();

        var first = await PostGateAsync(w, "2026.10", Sha('a'), "pass", flavor);
        var second = await PostGateAsync(w, "2026.10", Sha('b'), "fail", flavor);

        Assert.NotEqual(first, second);
        var builds = await BuildsAsync(w.ProjectId);
        Assert.Equal(2, builds.Count);
        Assert.Equal(Sha('a'), builds.Single(b => b.Id == first).CommitSha);
        Assert.Equal(Sha('b'), builds.Single(b => b.Id == second).CommitSha);
        // The first commit's evidence survives the second commit's replace-on-ingest.
        Assert.Equal("pass", await GateStatusAsync(first));
        Assert.Equal("fail", await GateStatusAsync(second));
    }

    [SkippableFact]
    public async Task The_same_commit_under_different_version_strings_is_one_build()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        var full = "6648825947dbe6bc1dbbbed01f7ef2f37804a9e9";

        var a = await PostGateAsync(w, "1.17.3", full[..7], "pass");
        var b = await PostGateAsync(w, "0.0.0+6648825", full, "pass");

        Assert.Equal(a, b);
        var build = Assert.Single(await BuildsAsync(w.ProjectId));
        Assert.Equal(full, build.CommitSha);   // converges on the fuller sha
    }

    [SkippableFact]
    public async Task A_build_created_before_its_commit_was_known_is_adopted_by_the_commit()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();

        var noSha = await PostGateAsync(w, "3.0.0", null, "pass");
        var withSha = await PostGateAsync(w, "3.0.0", Sha('c'), "pass");

        Assert.Equal(noSha, withSha);
        Assert.Equal(Sha('c'), Assert.Single(await BuildsAsync(w.ProjectId)).CommitSha);
    }

    [SkippableFact]
    public async Task Without_a_commit_the_version_string_still_identifies_the_build()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();

        var a = await PostGateAsync(w, "4.0.0", null, "pass");
        var b = await PostGateAsync(w, "4.0.0", null, "fail");

        Assert.Equal(a, b);
        Assert.Equal("fail", await GateStatusAsync(a));   // replace-on-ingest within one build, as before
    }

    [SkippableFact]
    public async Task A_pull_request_build_never_adopts_the_main_build_with_the_same_version()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();

        var main = await PostGateAsync(w, "5.0.0", Sha('d'), "pass");
        var pr = await PostGateAsync(w, "5.0.0", Sha('e'), "fail", pr: "refs/pull/7/merge");

        Assert.NotEqual(main, pr);
        Assert.Equal("pass", await GateStatusAsync(main));
    }
}
