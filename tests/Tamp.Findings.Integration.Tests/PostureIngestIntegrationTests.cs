using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Ingest;
using Tamp.Findings.Application.Risk;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Risk;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Integration.Tests;

// TFND-212: the producer reports posture over /ingest/posture; the latest observation per check is the
// current posture and feeds the per-check gate.
[Collection(DatabaseCollection.Name)]
public class PostureIngestIntegrationTests
{
    private readonly DatabaseFixture _fx;
    public PostureIngestIntegrationTests(DatabaseFixture fx) => _fx = fx;

    private sealed record World(Guid ProjectId, string ClientName, string ProjectName, string Token);

    private async Task<World> SeedAsync()
    {
        var s = Guid.NewGuid().ToString("N")[..8];
        Guid projectId, userId; string clientName, projectName;
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            var user = new User { Login = $"po-{s}", DisplayName = "po", Email = $"po{s}@e.test", IsApproved = true };
            var client = new Client { Name = $"po-client-{s}" };
            var project = new Project { ClientId = client.Id, Name = $"po-project-{s}" };
            db.Users.Add(user); db.Clients.Add(client); db.Projects.Add(project);
            await db.SaveChangesAsync();
            (projectId, userId, clientName, projectName) = (project.Id, user.Id, client.Name, project.Name);
        }
        string token;
        using (var scope = _fx.Scope())
            token = (await scope.ServiceProvider.GetRequiredService<IngestTokenService>()
                .MintProjectTokenAsync(projectId, "po-tok", userId, default)).Plaintext;
        return new World(projectId, clientName, projectName, token);
    }

    private HttpClient Http(World w)
    {
        var http = _fx.Factory!.CreateClient();
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", w.Token);
        return http;
    }

    private static object Body(World w, params (string Check, string Status, string? Detail)[] obs) => new
    {
        client = w.ClientName, project = w.ProjectName, source = "test",
        observations = obs.Select(o => new { checkId = o.Check, status = o.Status, detail = o.Detail }).ToArray(),
    };

    private async Task<RiskInputs> InputsAsync(World w)
    {
        using var scope = _fx.Scope();
        var policy = (await scope.ServiceProvider.GetRequiredService<ScoringPolicyResolver>().ForProjectAsync(w.ProjectId)).Config;
        return await scope.ServiceProvider.GetRequiredService<RiskInputsBuilder>().BuildAsync([Guid.NewGuid()], policy, w.ProjectId, default);
    }

    [SkippableFact]
    public async Task Posting_posture_records_it_and_re_posting_replaces_rather_than_duplicates()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        var http = Http(w);

        var first = await http.PostAsJsonAsync("/ingest/posture",
            Body(w, ("branch-protection", "pass", "protected"), ("signed-commits", "fail", "unsigned commits allowed")));
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);

        var second = await http.PostAsJsonAsync("/ingest/posture", Body(w, ("signed-commits", "pass", "now required")));
        Assert.Equal(HttpStatusCode.OK, second.StatusCode);

        using var scope = _fx.Scope();
        var rows = await _fx.Db(scope).PostureObservations.Where(o => o.ProjectId == w.ProjectId).ToListAsync();
        Assert.Equal(2, rows.Count);                                                   // not three
        Assert.Equal(PostureStatus.Pass, rows.Single(r => r.CheckId == "signed-commits").Status);
        Assert.Equal("now required", rows.Single(r => r.CheckId == "signed-commits").Detail);
        Assert.Equal(PostureStatus.Pass, rows.Single(r => r.CheckId == "branch-protection").Status);
    }

    [SkippableFact]
    public async Task An_unknown_check_or_status_is_rejected_and_nothing_in_the_batch_is_written()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        var http = Http(w);

        var badCheck = await http.PostAsJsonAsync("/ingest/posture",
            Body(w, ("branch-protection", "pass", null), ("made-up-check", "pass", null)));
        var badStatus = await http.PostAsJsonAsync("/ingest/posture", Body(w, ("codeowners", "maybe", null)));

        Assert.Equal(HttpStatusCode.BadRequest, badCheck.StatusCode);
        Assert.Contains("made-up-check", await badCheck.Content.ReadAsStringAsync());
        Assert.Equal(HttpStatusCode.BadRequest, badStatus.StatusCode);
        using var scope = _fx.Scope();
        Assert.False(await _fx.Db(scope).PostureObservations.AnyAsync(o => o.ProjectId == w.ProjectId));
    }

    [SkippableFact]
    public async Task A_token_for_another_project_cannot_report_posture()
    {
        Skip.IfNot(_fx.Available);
        var mine = await SeedAsync();
        var other = await SeedAsync();
        var http = Http(mine);

        var resp = await http.PostAsJsonAsync("/ingest/posture", Body(other, ("branch-protection", "pass", null)));

        Assert.NotEqual(HttpStatusCode.OK, resp.StatusCode);
        using var scope = _fx.Scope();
        Assert.False(await _fx.Db(scope).PostureObservations.AnyAsync(o => o.ProjectId == other.ProjectId));
    }

    [SkippableFact]
    public async Task Posture_flows_into_the_gate_inputs_and_an_unauthenticated_post_is_refused()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        Assert.True((await InputsAsync(w)).Posture is null or { Count: 0 });

        var ok = await Http(w).PostAsJsonAsync("/ingest/posture", Body(w, ("org-2fa", "fail", "2FA optional")));
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);

        var reading = (await InputsAsync(w)).Posture!["org-2fa"];
        Assert.Equal(PostureStatus.Fail, reading.Status);
        Assert.Equal("2FA optional", reading.Detail);

        var anon = await _fx.Factory!.CreateClient().PostAsJsonAsync("/ingest/posture", Body(w, ("org-2fa", "pass", null)));
        Assert.Equal(HttpStatusCode.Unauthorized, anon.StatusCode);
    }
}
