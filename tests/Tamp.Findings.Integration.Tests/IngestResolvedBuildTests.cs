using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Ingest;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Integration.Tests;

// TFND-266: an ingest response says what the server STORED and which build it landed on, not just "200". A producer
// can then log the resolved commit and compare it with the one it sent, instead of logging only its own request.
[Collection(DatabaseCollection.Name)]
public class IngestResolvedBuildTests
{
    private readonly DatabaseFixture _fx;
    public IngestResolvedBuildTests(DatabaseFixture fx) => _fx = fx;

    private async Task<(HttpClient Http, string Client, string Project)> SeedAsync()
    {
        var s = Guid.NewGuid().ToString("N")[..8];
        Guid projectId, userId; string clientName, projectName;
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            var user = new User { Login = $"irb-{s}", DisplayName = "i", Email = $"i{s}@e.test", IsApproved = true };
            var client = new Client { Name = $"irb-c-{s}" };
            var project = new Project { ClientId = client.Id, Name = $"irb-p-{s}" };
            db.Users.Add(user); db.Clients.Add(client); db.Projects.Add(project);
            await db.SaveChangesAsync();
            (projectId, userId, clientName, projectName) = (project.Id, user.Id, client.Name, project.Name);
        }
        string token;
        using (var scope = _fx.Scope())
            token = (await scope.ServiceProvider.GetRequiredService<IngestTokenService>()
                .MintProjectTokenAsync(projectId, "irb", userId, default)).Plaintext;
        var http = _fx.Factory!.CreateClient();
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return (http, clientName, projectName);
    }

    [SkippableFact]
    public async Task Every_single_build_ingest_names_the_build_it_landed_on()
    {
        Skip.IfNot(_fx.Available);
        var (http, client, project) = await SeedAsync();
        var sha = "f00dfeed" + new string('1', 32);
        var ctx = new { client, project, version = "9.9.9", commitSha = sha, branch = "main" };

        var gate = await http.PostAsJsonAsync("/ingest/quality-gate", new { ctx.client, ctx.project, ctx.version, ctx.commitSha, ctx.branch, status = "pass" });
        var receipts = await http.PostAsJsonAsync("/ingest/scan-runs", new
        {
            ctx.client, ctx.project, ctx.version, ctx.commitSha, ctx.branch,
            receipts = new[] { new { scanner = "OpenGrep", status = "Succeeded", startedAt = DateTimeOffset.UtcNow, completedAt = DateTimeOffset.UtcNow, findingsCount = 0 } },
        });
        var findings = await http.PostAsJsonAsync("/ingest/findings", new
        {
            ctx.client, ctx.project, ctx.version, ctx.commitSha, ctx.branch, scanner = "OpenGrep",
            findings = new[] { new { ruleId = "r1", severity = "High", title = "t", filePath = "a.cs", line = 1 } },
        });

        var ids = new List<Guid>();
        foreach (var resp in new[] { gate, receipts, findings })
        {
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
            var body = await resp.Content.ReadFromJsonAsync<JsonElement>();
            var build = body.GetProperty("build");
            Assert.Equal(sha, build.GetProperty("commitSha").GetString());
            Assert.Equal("9.9.9", build.GetProperty("versionString").GetString());
            Assert.Equal("main", build.GetProperty("branch").GetString());
            Assert.Equal(body.GetProperty("componentVersionId").GetGuid(), build.GetProperty("componentVersionId").GetGuid());
            ids.Add(build.GetProperty("componentVersionId").GetGuid());
        }
        Assert.Single(ids.Distinct());   // three kinds of evidence, one commit, one build — and the responses say so
    }

    [SkippableFact]
    public async Task The_echo_reveals_when_evidence_lands_on_a_build_created_under_another_version_string()
    {
        Skip.IfNot(_fx.Available);
        var (http, client, project) = await SeedAsync();
        var sha = "beadcafe" + new string('2', 32);

        await http.PostAsJsonAsync("/ingest/quality-gate", new { client, project, version = "1.0.0", commitSha = sha, status = "pass" });
        var second = await http.PostAsJsonAsync("/ingest/quality-gate", new { client, project, version = "1.0.0+different", commitSha = sha, status = "pass" });

        // Same commit, so the same build — and the producer can SEE that its version string was not the build's.
        var build = (await second.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("build");
        Assert.Equal(sha, build.GetProperty("commitSha").GetString());
        Assert.Equal("1.0.0", build.GetProperty("versionString").GetString());
    }
}
