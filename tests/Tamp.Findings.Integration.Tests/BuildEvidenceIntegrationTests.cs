using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Ingest;

namespace Tamp.Findings.Integration.Tests;

// TFND-265: the ingest token that posted a commit's evidence can read back what the server holds for it. Before this a
// producer's only confirmation was the 200 it got, and checking that a nightly's coverage landed needed a signed-in user.
[Collection(DatabaseCollection.Name)]
public class BuildEvidenceIntegrationTests
{
    private readonly DatabaseFixture _fx;
    public BuildEvidenceIntegrationTests(DatabaseFixture fx) => _fx = fx;

    private static string NewSha() => Guid.NewGuid().ToString("N") + "abcdef01";

    private HttpClient Http(string? token)
    {
        var http = _fx.Factory!.CreateClient();
        if (token is not null) http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return http;
    }

    private async Task<string> ClientTokenAsync(Guid clientId, Guid userId)
    {
        using var scope = _fx.Scope();
        return (await scope.ServiceProvider.GetRequiredService<IngestTokenService>()
            .MintClientTokenAsync(clientId, "readback-cli", userId, default)).Plaintext;
    }

    [SkippableFact]
    public async Task The_token_that_posted_a_commit_reads_back_every_kind_of_evidence_it_holds()
    {
        Skip.IfNot(_fx.Available);
        var w = await PageAWorld.SeedAsync(_fx);
        var sha = NewSha();
        await PageAIngest.IngestBuildAsync(_fx, w, sha, "4.5.6");
        var http = Http(await PageAIngest.MintTokenAsync(_fx, w.Project.Id, w.Admin.Id));

        var resp = await http.GetAsync($"/ingest/builds/{sha}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var body = await resp.Content.ReadFromJsonAsync<JsonElement>();

        Assert.Equal(w.Project.Id, body.GetProperty("projectId").GetGuid());
        Assert.Equal(w.Project.Name, body.GetProperty("project").GetString());
        var build = Assert.Single(body.GetProperty("builds").EnumerateArray().ToList());
        Assert.Equal(sha, build.GetProperty("build").GetProperty("commitSha").GetString());
        Assert.Equal("4.5.6", build.GetProperty("build").GetProperty("versionString").GetString());

        var cov = build.GetProperty("coverage");
        Assert.Equal(JsonValueKind.Object, cov.ValueKind);
        Assert.True(cov.GetProperty("modules").GetInt32() > 0, "coverage modules were stored");

        var tests = build.GetProperty("testResults");
        Assert.Equal(JsonValueKind.Object, tests.ValueKind);
        Assert.True(tests.GetProperty("suites").GetInt32() > 0);
        Assert.True(tests.GetProperty("cases").GetInt32() > 0);

        var sbom = build.GetProperty("sbom");
        Assert.Equal(JsonValueKind.Object, sbom.ValueKind);
        Assert.True(sbom.GetProperty("components").GetInt32() > 0);

        var findings = build.GetProperty("findings").EnumerateArray().ToList();
        Assert.True(findings.Count >= 2, "findings are grouped per scanner");
        Assert.All(findings, f => Assert.True(f.GetProperty("total").GetInt32() >= f.GetProperty("open").GetInt32()));
        Assert.NotEmpty(build.GetProperty("scanRuns").EnumerateArray());

        // Summaries only: no finding bodies, file paths or source come back.
        var raw = await resp.Content.ReadAsStringAsync();
        Assert.DoesNotContain("\"filePath\"", raw);
        Assert.DoesNotContain("\"snippet\"", raw);
    }

    [SkippableFact]
    public async Task A_short_sha_reads_the_same_build_as_the_full_one()
    {
        Skip.IfNot(_fx.Available);
        var w = await PageAWorld.SeedAsync(_fx);
        var sha = NewSha();
        var http = Http(await PageAIngest.MintTokenAsync(_fx, w.Project.Id, w.Admin.Id));
        var post = await http.PostAsJsonAsync("/ingest/quality-gate",
            new { client = w.Client.Name, project = w.Project.Name, version = "1.0.0", commitSha = sha, status = "pass" });
        Assert.Equal(HttpStatusCode.OK, post.StatusCode);

        var full = await http.GetFromJsonAsync<JsonElement>($"/ingest/builds/{sha}");
        var shortRead = await http.GetFromJsonAsync<JsonElement>($"/ingest/builds/{sha[..7].ToUpperInvariant()}");
        Guid Id(JsonElement e) => e.GetProperty("builds")[0].GetProperty("build").GetProperty("componentVersionId").GetGuid();
        Assert.Equal(Id(full), Id(shortRead));
        Assert.Equal("pass", full.GetProperty("builds")[0].GetProperty("qualityGate").GetProperty("status").GetString());
        // Nothing else was posted, so the other sections read as absent rather than empty-but-present.
        Assert.Equal(JsonValueKind.Null, full.GetProperty("builds")[0].GetProperty("coverage").ValueKind);
    }

    [SkippableFact]
    public async Task Two_commits_with_one_version_read_back_as_two_builds()
    {
        Skip.IfNot(_fx.Available);
        var w = await PageAWorld.SeedAsync(_fx);
        var (a, b) = (NewSha(), NewSha());
        var http = Http(await PageAIngest.MintTokenAsync(_fx, w.Project.Id, w.Admin.Id));
        await http.PostAsJsonAsync("/ingest/quality-gate", new { client = w.Client.Name, project = w.Project.Name, version = "7.0.0", commitSha = a, status = "pass" });
        await http.PostAsJsonAsync("/ingest/quality-gate", new { client = w.Client.Name, project = w.Project.Name, version = "7.0.0", commitSha = b, status = "fail" });

        var ra = (await http.GetFromJsonAsync<JsonElement>($"/ingest/builds/{a}")).GetProperty("builds")[0];
        var rb = (await http.GetFromJsonAsync<JsonElement>($"/ingest/builds/{b}")).GetProperty("builds")[0];
        Assert.Equal("pass", ra.GetProperty("qualityGate").GetProperty("status").GetString());
        Assert.Equal("fail", rb.GetProperty("qualityGate").GetProperty("status").GetString());
        Assert.NotEqual(ra.GetProperty("build").GetProperty("componentVersionId").GetGuid(),
                        rb.GetProperty("build").GetProperty("componentVersionId").GetGuid());
    }

    [SkippableFact]
    public async Task Every_flavor_of_a_commit_comes_back_and_flavor_narrows_to_one()
    {
        Skip.IfNot(_fx.Available);
        var w = await PageAWorld.SeedAsync(_fx);
        var sha = NewSha();
        var http = Http(await PageAIngest.MintTokenAsync(_fx, w.Project.Id, w.Admin.Id));
        foreach (var flavor in new[] { "linux", "windows" })
            await http.PostAsJsonAsync("/ingest/quality-gate",
                new { client = w.Client.Name, project = w.Project.Name, version = "1.0.0", commitSha = sha, flavor, status = "pass" });

        var all = await http.GetFromJsonAsync<JsonElement>($"/ingest/builds/{sha}");
        Assert.Equal(2, all.GetProperty("builds").GetArrayLength());

        var one = await http.GetFromJsonAsync<JsonElement>($"/ingest/builds/{sha}?flavor=LINUX");
        var only = Assert.Single(one.GetProperty("builds").EnumerateArray().ToList());
        Assert.Equal("linux", only.GetProperty("build").GetProperty("flavor").GetString());
    }

    [SkippableFact]
    public async Task A_project_token_cannot_read_a_sibling_project_and_cannot_tell_it_exists()
    {
        Skip.IfNot(_fx.Available);
        var w = await PageAWorld.SeedAsync(_fx);
        var sha = NewSha();
        var sibling = Http(await PageAIngest.MintTokenAsync(_fx, w.Project2.Id, w.Admin.Id));
        await sibling.PostAsJsonAsync("/ingest/quality-gate",
            new { client = w.Client.Name, project = w.Project2.Name, version = "1.0.0", commitSha = sha, status = "pass" });
        Assert.Equal(HttpStatusCode.OK, (await sibling.GetAsync($"/ingest/builds/{sha}")).StatusCode);

        var other = Http(await PageAIngest.MintTokenAsync(_fx, w.Project.Id, w.Admin.Id));
        // Its own project has no such commit; naming the sibling does not widen the token.
        Assert.Equal(HttpStatusCode.NotFound, (await other.GetAsync($"/ingest/builds/{sha}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound,
            (await other.GetAsync($"/ingest/builds/{sha}?project={Uri.EscapeDataString(w.Project2.Name)}")).StatusCode);
    }

    [SkippableFact]
    public async Task A_client_token_reads_any_project_under_its_client_by_name_and_nothing_outside_it()
    {
        Skip.IfNot(_fx.Available);
        var w = await PageAWorld.SeedAsync(_fx);
        var sha = NewSha();
        var cli = Http(await ClientTokenAsync(w.Client.Id, w.Admin.Id));
        await cli.PostAsJsonAsync("/ingest/quality-gate",
            new { client = w.Client.Name, project = w.Project2.Name, version = "1.0.0", commitSha = sha, status = "warn" });

        Assert.Equal(HttpStatusCode.BadRequest, (await cli.GetAsync($"/ingest/builds/{sha}")).StatusCode);
        var ok = await cli.GetAsync($"/ingest/builds/{sha}?project={Uri.EscapeDataString(w.Project2.Name.ToUpperInvariant())}");
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);

        // Another client's token sees nothing, even naming the right project.
        var foreign = Http(await ClientTokenAsync(w.EmptyClient.Id, w.Admin.Id));
        Assert.Equal(HttpStatusCode.NotFound,
            (await foreign.GetAsync($"/ingest/builds/{sha}?project={Uri.EscapeDataString(w.Project2.Name)}")).StatusCode);
    }

    [SkippableFact]
    public async Task Reading_never_creates_a_project_the_way_ingest_would()
    {
        Skip.IfNot(_fx.Available);
        var w = await PageAWorld.SeedAsync(_fx);
        var cli = Http(await ClientTokenAsync(w.Client.Id, w.Admin.Id));
        var name = $"never-made-{w.S}";

        Assert.Equal(HttpStatusCode.NotFound, (await cli.GetAsync($"/ingest/builds/{NewSha()}?project={name}")).StatusCode);

        using var scope = _fx.Scope();
        Assert.False(await _fx.Db(scope).Projects.AnyAsync(p => p.Name == name));
    }

    [SkippableFact]
    public async Task Bad_requests_are_refused_before_anything_is_looked_up()
    {
        Skip.IfNot(_fx.Available);
        var w = await PageAWorld.SeedAsync(_fx);
        var http = Http(await PageAIngest.MintTokenAsync(_fx, w.Project.Id, w.Admin.Id));

        Assert.Equal(HttpStatusCode.Unauthorized, (await Http(null).GetAsync($"/ingest/builds/{NewSha()}")).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await http.GetAsync("/ingest/builds/abc12")).StatusCode);        // too short
        Assert.Equal(HttpStatusCode.BadRequest, (await http.GetAsync("/ingest/builds/not-a-commit")).StatusCode); // not hex
        Assert.Equal(HttpStatusCode.NotFound, (await http.GetAsync($"/ingest/builds/{NewSha()}")).StatusCode);    // unknown
    }
}
