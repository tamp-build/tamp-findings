using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Ingest;
using Tamp.Findings.Domain.Compliance;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Integration.Tests;

// ADR-conformance evidence ingest (core ADR 0023). The producer POSTs the
// canonical BuildEvent stream; findings keeps conformance.evaluated and binds
// each verdict to a build by provenance.commitSha. Verdicts are frozen at
// ingest and a re-run upserts rather than duplicates.
[Collection(DatabaseCollection.Name)]
public class ConformanceIngestIntegrationTests
{
    private readonly DatabaseFixture _fx;

    public ConformanceIngestIntegrationTests(DatabaseFixture fx) => _fx = fx;

    private const string Sha = "abc123def456";

    private async Task<(Guid ProjectId, Guid CvId, Guid UserId)> SeedBuildAsync()
    {
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var suffix = Guid.NewGuid().ToString("N")[..8];

        var user = new User { Login = $"cf-{suffix}", DisplayName = "CF", Email = $"cf-{suffix}@example.test", IsApproved = true };
        var client = new Client { Name = $"cf-client-{suffix}" };
        var project = new Project { ClientId = client.Id, Name = $"cf-project-{suffix}" };
        var cv = new ComponentVersion { ProjectId = project.Id, VersionString = "1.0.0", CommitSha = Sha };
        db.AddRange(user, client, project, cv);
        await db.SaveChangesAsync();
        return (project.Id, cv.Id, user.Id);
    }

    private async Task<string> MintProjectTokenAsync(Guid projectId, Guid userId)
    {
        using var scope = _fx.Scope();
        var tokens = scope.ServiceProvider.GetRequiredService<IngestTokenService>();
        return (await tokens.MintProjectTokenAsync(projectId, "cf-tok", userId, default)).Plaintext;
    }

    // Build a canonical BuildEvent (conformance.evaluated) as valid JSON via the
    // serializer, so nested braces never fight a raw-string literal.
    private static string Event(string verdict, string method = "deterministic", string adrRef = "0002",
        string ruleId = "0002-r1", bool blocks = true, string? verify = null)
    {
        var payload = new Dictionary<string, object?>
        {
            ["$type"] = "conformance.evaluated", ["adrRef"] = adrRef, ["ruleId"] = ruleId,
            ["verdict"] = verdict, ["method"] = method, ["blocks"] = blocks,
            ["controlRefs"] = new[] { "CM-6", "AC-3" },
        };
        if (verdict == "fail")
        {
            payload["adrQuote"] = "the rule text";
            payload["codeEvidence"] = "bad();";
            payload["location"] = new Dictionary<string, object?> { ["file"] = "src/X.cs", ["line"] = 9 };
        }
        var prov = new Dictionary<string, object?> { ["commitSha"] = Sha, ["rulesSha"] = "sha256:aa" };
        if (verify is not null) prov["verifyVerdict"] = verify;
        payload["provenance"] = prov;

        var ev = new Dictionary<string, object?>
        {
            ["schemaVersion"] = "1.0", ["ts"] = "2026-09-28T18:00:00Z", ["type"] = "conformance.evaluated",
            ["buildId"] = "b1", ["runId"] = "r1", ["targetId"] = "CheckAdrConformance",
            ["traceId"] = "b1", ["spanId"] = "s1", ["workerId"] = "agent:conformance", ["seq"] = 1,
            ["payload"] = payload,
        };
        return JsonSerializer.Serialize(ev);
    }

    private HttpClient Client(string token)
    {
        var http = _fx.Factory!.CreateClient();
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return http;
    }

    private static StringContent Json(string body) => new(body, Encoding.UTF8, "application/json");

    [SkippableFact]
    public async Task A_conformance_verdict_binds_to_the_build_and_is_readable()
    {
        Skip.IfNot(_fx.Available);
        var (projectId, _, userId) = await SeedBuildAsync();
        using var http = Client(await MintProjectTokenAsync(projectId, userId));

        // A JSON array with one fail verdict.
        var resp = await http.PostAsync("/ingest/conformance", Json($"[{Event("fail", verify: "fail")}]"));
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        using var scope = _fx.Scope();
        var q = scope.ServiceProvider.GetRequiredService<Application.Compliance.ConformanceQuery>();
        var report = await q.ForProjectAsync(projectId, Sha);

        Assert.NotNull(report);
        Assert.Equal(1, report!.Fail);
        var f = Assert.Single(report.Findings);
        Assert.Equal("0002", f.AdrRef);
        Assert.Equal(ConformanceVerdict.Fail, f.Verdict);
        Assert.Equal(VerifyOutcome.Confirmed, f.VerifyVerdict);   // verifyVerdict "fail" == verdict Fail
        Assert.Contains("CM-6", f.ControlRefs);
        Assert.Equal("src/X.cs:9", f.Location);
    }

    [SkippableFact]
    public async Task Non_conformance_events_are_skipped_not_stored()
    {
        Skip.IfNot(_fx.Available);
        var (projectId, _, userId) = await SeedBuildAsync();
        using var http = Client(await MintProjectTokenAsync(projectId, userId));

        // A gate.evaluated event (different $type) alongside one conformance one.
        const string gate = """{"type":"gate.evaluated","buildId":"b1","seq":2,"payload":{"$type":"gate.evaluated","key":"kev","verdict":"pass"}}""";
        var body = $"[{gate},{Event("pass")}]";
        var resp = await http.PostAsync("/ingest/conformance", Json(body));

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        using var scope = _fx.Scope();
        var q = scope.ServiceProvider.GetRequiredService<Application.Compliance.ConformanceQuery>();
        var report = await q.ForProjectAsync(projectId, Sha);
        Assert.Equal(1, report!.Pass);              // only the conformance one
        Assert.Single(report.Findings);
    }

    [SkippableFact]
    public async Task Ndjson_body_is_accepted()
    {
        Skip.IfNot(_fx.Available);
        var (projectId, _, userId) = await SeedBuildAsync();
        using var http = Client(await MintProjectTokenAsync(projectId, userId));

        var ndjson = string.Join('\n',
            Event("pass", ruleId: "0002-r1").ReplaceLineEndings(" "),
            Event("unknown", adrRef: "0004", ruleId: "0004-r1").ReplaceLineEndings(" "));
        var resp = await http.PostAsync("/ingest/conformance", new StringContent(ndjson, Encoding.UTF8, "application/x-ndjson"));

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        using var scope = _fx.Scope();
        var q = scope.ServiceProvider.GetRequiredService<Application.Compliance.ConformanceQuery>();
        var report = await q.ForProjectAsync(projectId, Sha);
        Assert.Equal(2, report!.Findings.Count);
        Assert.Equal(1, report.Unknown);
    }

    [SkippableFact]
    public async Task A_re_run_upserts_rather_than_duplicating()
    {
        Skip.IfNot(_fx.Available);
        var (projectId, _, userId) = await SeedBuildAsync();
        using var http = Client(await MintProjectTokenAsync(projectId, userId));

        await http.PostAsync("/ingest/conformance", Json($"[{Event("fail")}]"));
        // Same (build, adrRef, ruleId), now passing.
        await http.PostAsync("/ingest/conformance", Json($"[{Event("pass")}]"));

        using var scope = _fx.Scope();
        var q = scope.ServiceProvider.GetRequiredService<Application.Compliance.ConformanceQuery>();
        var report = await q.ForProjectAsync(projectId, Sha);
        Assert.Single(report!.Findings);            // not duplicated
        Assert.Equal(ConformanceVerdict.Pass, report.Findings[0].Verdict);   // newest verdict wins
    }

    [SkippableFact]
    public async Task A_verdict_for_an_unknown_commit_is_skipped()
    {
        Skip.IfNot(_fx.Available);
        var (projectId, _, userId) = await SeedBuildAsync();
        using var http = Client(await MintProjectTokenAsync(projectId, userId));

        var evt = Event("fail").Replace(Sha, "no-such-commit");
        var resp = await http.PostAsync("/ingest/conformance", Json($"[{evt}]"));

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var body = await resp.Content.ReadAsStringAsync();
        Assert.Contains("\"skipped\":1", body);
        Assert.Contains("\"accepted\":0", body);
    }

    [SkippableFact]
    public async Task A_missing_token_is_401()
    {
        Skip.IfNot(_fx.Available);
        using var http = _fx.Factory!.CreateClient();
        var resp = await http.PostAsync("/ingest/conformance", Json($"[{Event("pass")}]"));
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }
}
