using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Ingest;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Integration.Tests;

// Reverse-examination advisory ingest (ADR 0013 / TFND-197). The producer POSTs the canonical
// BuildEvent stream to /ingest/diagnostics; findings keeps only diagnostic.emitted notes whose
// ruleId is undocumented-decision:<kind>, binds each to a build by provenance.commitSha, and
// upserts by (build, ruleId, location). Advisory-only — nothing here gates.
[Collection(DatabaseCollection.Name)]
public class DecisionDiagnosticIngestIntegrationTests
{
    private readonly DatabaseFixture _fx;
    public DecisionDiagnosticIngestIntegrationTests(DatabaseFixture fx) => _fx = fx;

    // A unique commit sha per seeded build — the whole DB is shared across tests, and multiple
    // CVs carrying the same sha would blur which build a note binds to.
    private async Task<(Guid ProjectId, Guid UserId, string Sha)> SeedBuildAsync()
    {
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var s = Guid.NewGuid().ToString("N")[..8];
        var sha = $"dd{s}commit";
        var user = new User { Login = $"dd-{s}", DisplayName = "DD", Email = $"dd-{s}@example.test", IsApproved = true };
        var client = new Client { Name = $"dd-client-{s}" };
        var project = new Project { ClientId = client.Id, Name = $"dd-project-{s}" };
        var component = new Component { ProjectId = project.Id, Name = $"dd-comp-{s}" };
        var cv = new ComponentVersion { ProjectId = component.ProjectId, ComponentId = component.Id, VersionString = "1.0.0", CommitSha = sha };
        db.AddRange(user, client, project, component, cv);
        await db.SaveChangesAsync();
        return (project.Id, user.Id, sha);
    }

    private async Task<string> MintTokenAsync(Guid projectId, Guid userId)
    {
        using var scope = _fx.Scope();
        var tokens = scope.ServiceProvider.GetRequiredService<IngestTokenService>();
        return (await tokens.MintProjectTokenAsync(projectId, "dd-tok", userId, default)).Plaintext;
    }

    private static string Note(string sha, string kind, string message, string file = "src/Y.cs", int line = 3)
    {
        var payload = new Dictionary<string, object?>
        {
            ["$type"] = "diagnostic.emitted",
            ["ruleId"] = $"undocumented-decision:{kind}",
            ["level"] = "note",
            ["message"] = message,
            ["location"] = new Dictionary<string, object?> { ["file"] = file, ["line"] = line },
            ["provenance"] = new Dictionary<string, object?> { ["commitSha"] = sha },
        };
        var ev = new Dictionary<string, object?>
        {
            ["type"] = "diagnostic.emitted", ["buildId"] = "b1", ["runId"] = "r1", ["seq"] = 1,
            ["workerId"] = "agent:conformance", ["payload"] = payload,
        };
        return JsonSerializer.Serialize(ev);
    }

    private HttpClient Http(string token)
    {
        var http = _fx.Factory!.CreateClient();
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return http;
    }

    private static StringContent Json(string body) => new(body, Encoding.UTF8, "application/json");

    [SkippableFact]
    public async Task An_undocumented_decision_note_binds_to_the_build_and_is_readable()
    {
        Skip.IfNot(_fx.Available);
        var (projectId, userId, sha) = await SeedBuildAsync();
        using var http = Http(await MintTokenAsync(projectId, userId));

        var resp = await http.PostAsync("/ingest/diagnostics",
            Json($"[{Note(sha, "new-dependency", "Adds Serilog; no ADR records the logging-stack choice.")}]"));
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        using var scope = _fx.Scope();
        var q = scope.ServiceProvider.GetRequiredService<Application.Compliance.DecisionDiagnosticsQuery>();
        var report = await q.ForProjectAsync(projectId, sha);

        Assert.NotNull(report);
        var d = Assert.Single(report!.Decisions);
        Assert.Equal("new-dependency", d.Kind);
        Assert.Equal("undocumented-decision:new-dependency", d.RuleId);
        Assert.Equal("src/Y.cs:3", d.Location);
        Assert.Contains("CM-3", d.ControlRefs);     // defaulted CM-3 mapping
        Assert.Contains("Serilog", d.Summary);
    }

    [SkippableFact]
    public async Task Non_undocumented_decision_events_are_skipped()
    {
        Skip.IfNot(_fx.Available);
        var (projectId, userId, sha) = await SeedBuildAsync();
        using var http = Http(await MintTokenAsync(projectId, userId));

        // A conformance verdict and a plain diagnostic (non-undocumented ruleId) alongside one note.
        const string conf = """{"type":"conformance.evaluated","seq":1,"payload":{"$type":"conformance.evaluated","adrRef":"0002","ruleId":"r","verdict":"pass"}}""";
        var other = JsonSerializer.Serialize(new Dictionary<string, object?>
        {
            ["type"] = "diagnostic.emitted", ["seq"] = 2,
            ["payload"] = new Dictionary<string, object?>
            {
                ["$type"] = "diagnostic.emitted", ["ruleId"] = "style:naming", ["level"] = "note", ["message"] = "x",
                ["provenance"] = new Dictionary<string, object?> { ["commitSha"] = sha },
            },
        });
        var resp = await http.PostAsync("/ingest/diagnostics", Json($"[{conf},{other},{Note(sha, "new-endpoint", "New /admin route with no ADR.")}]"));

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        using var scope = _fx.Scope();
        var q = scope.ServiceProvider.GetRequiredService<Application.Compliance.DecisionDiagnosticsQuery>();
        var report = await q.ForProjectAsync(projectId, sha);
        var d = Assert.Single(report!.Decisions);     // only the undocumented-decision note
        Assert.Equal("new-endpoint", d.Kind);
    }

    [SkippableFact]
    public async Task Re_ingest_upserts_by_build_rule_and_location()
    {
        Skip.IfNot(_fx.Available);
        var (projectId, userId, sha) = await SeedBuildAsync();
        using var http = Http(await MintTokenAsync(projectId, userId));

        await http.PostAsync("/ingest/diagnostics", Json($"[{Note(sha, "new-dependency", "first summary")}]"));
        var resp = await http.PostAsync("/ingest/diagnostics", Json($"[{Note(sha, "new-dependency", "revised summary")}]"));
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var rows = await db.DecisionDiagnostics
            .Where(d => d.RuleId == "undocumented-decision:new-dependency" && d.CommitSha == sha).ToListAsync();
        var row = Assert.Single(rows);                 // upsert, not duplicate
        Assert.Equal("revised summary", row.Summary);  // newest wins
    }
}
