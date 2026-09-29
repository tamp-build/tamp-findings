using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Api.Contracts;
using Tamp.Findings.Application.Ingest;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Integration.Tests;

// TFND-20 ingest. The suite store keys one row per (assembly, class) — a .trx can split one class
// across several result groups, and a producer's mapper may chunk them however it likes, so the
// endpoint MUST merge rather than 500 on a duplicate key. Regression for the /ingest/test-results
// dup-key crash (IX_TestSuiteResults_TestRunReportId_..._ClassName).
[Collection(DatabaseCollection.Name)]
public class TestResultsIngestIntegrationTests
{
    private readonly DatabaseFixture _fx;
    public TestResultsIngestIntegrationTests(DatabaseFixture fx) => _fx = fx;

    private async Task<(string Client, string Project, string Token)> SeedProjectTokenAsync(string s)
    {
        Guid projectId, userId; string clientName, projectNm;
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            var user = new User { Login = $"tr-{s}", DisplayName = "tr", Email = $"tr{s}@e.test", IsApproved = true };
            db.Users.Add(user);
            var client = new Client { Name = $"tr-{s}" };
            db.Clients.Add(client);
            var project = new Project { ClientId = client.Id, Name = $"trp-{s}" };
            db.Projects.Add(project);
            await db.SaveChangesAsync();
            (projectId, userId, clientName, projectNm) = (project.Id, user.Id, client.Name, project.Name);
        }

        using var tscope = _fx.Scope();
        var token = (await tscope.ServiceProvider.GetRequiredService<IngestTokenService>()
            .MintProjectTokenAsync(projectId, "tr-tok", userId, default)).Plaintext;
        return (clientName, projectNm, token);
    }

    private static TestSuiteRequestDto Suite(string assembly, string className, int passed, int failed) =>
        new(assembly, className, passed + failed, passed, failed, 0, 0, 10,
            [new TestCaseRequestDto($"{className}.t", failed > 0 ? TestOutcome.Failed : TestOutcome.Passed, 4, null, null)]);

    [SkippableFact]
    public async Task Ingest_merges_suites_that_share_an_assembly_and_class()
    {
        Skip.IfNot(_fx.Available);
        var s = Guid.NewGuid().ToString("N")[..8];
        var (client, project, token) = await SeedProjectTokenAsync(s);

        var http = _fx.Factory!.CreateClient();
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        // Two groups reporting the SAME (assembly, class) — the shape that used to 500 on the
        // unique index — plus a same-class-different-assembly pair that must stay two rows.
        var req = new TestResultsIngestRequest(
            client, project, null, null, null, "1.0.0", $"{s}sha", "main", null, null,
            "dotnet test (trx)", null,
            TotalCount: 6, PassedCount: 4, FailedCount: 2, SkippedCount: 0, InconclusiveCount: 0,
            DurationMs: 40, StartedAt: DateTimeOffset.UtcNow.AddSeconds(-40), CompletedAt: DateTimeOffset.UtcNow,
            Suites:
            [
                Suite("Asm.A.dll", "Shared.Suite", passed: 1, failed: 0),
                Suite("Asm.A.dll", "Shared.Suite", passed: 1, failed: 1),  // dup (assembly, class) → merge
                Suite("Asm.B.dll", "Shared.Suite", passed: 2, failed: 1),  // same class, other assembly → distinct
            ]);

        var resp = await http.PostAsJsonAsync("/ingest/test-results", req);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var body = await resp.Content.ReadFromJsonAsync<TestResultsIngestResponse>();
        Assert.NotNull(body);
        Assert.Equal(2, body!.SuitesCount);   // (A, Shared) merged into one; (B, Shared) its own
        Assert.Equal(3, body.CasesCount);      // one case per input suite, all carried through the merge

        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var suites = await db.TestSuiteResults
            .Where(x => x.Report!.ComponentVersion!.CommitSha == $"{s}sha")
            .OrderBy(x => x.AssemblyName)
            .ToListAsync();
        Assert.Equal(2, suites.Count);
        var merged = suites.Single(x => x.AssemblyName == "Asm.A.dll");
        Assert.Equal("Shared.Suite", merged.ClassName);
        Assert.Equal(3, merged.TotalCount);   // (1+0) + (1+1) merged
        Assert.Equal(2, merged.PassedCount);
        Assert.Equal(1, merged.FailedCount);
    }
}
