using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
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

    [SkippableFact]
    public async Task Multiple_files_for_one_build_accumulate_and_replace_per_assembly()
    {
        Skip.IfNot(_fx.Available);
        var s = Guid.NewGuid().ToString("N")[..8];
        var (client, project, token) = await SeedProjectTokenAsync(s);
        var http = _fx.Factory!.CreateClient();
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        var sha = $"{s}multi";

        async Task<TestResultsIngestResponse> Post(params TestSuiteRequestDto[] suites)
        {
            var req = new TestResultsIngestRequest(client, project, null, null, null, "1.0.0", sha, "main", null, null,
                "dotnet test (trx)", null, 0, 0, 0, 0, 0, 0,
                DateTimeOffset.UtcNow.AddSeconds(-1), DateTimeOffset.UtcNow, suites);
            var resp = await http.PostAsJsonAsync("/ingest/test-results", req);
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
            return (await resp.Content.ReadFromJsonAsync<TestResultsIngestResponse>())!;
        }

        // Producer posts one file per test project — the shape that used to undercount (last-wins).
        await Post(Suite("Core.dll", "Core.T", passed: 10, failed: 0));
        await Post(Suite("Cli.dll", "Cli.T", passed: 5, failed: 1));

        async Task<(int total, int failed, int reports)> Rollup()
        {
            using var scope = _fx.Scope();
            var db = _fx.Db(scope);
            var report = await db.TestRunReports.SingleAsync(r => r.ComponentVersion!.CommitSha == sha);
            var suiteTotal = await db.TestSuiteResults.Where(x => x.TestRunReportId == report.Id).SumAsync(x => x.TotalCount);
            var reports = await db.TestRunReports.CountAsync(r => r.ComponentVersion!.CommitSha == sha);
            return (report.TotalCount, report.FailedCount, reports);
        }

        var after2 = await Rollup();
        Assert.Equal(1, after2.reports);          // one report per build, not two
        Assert.Equal(16, after2.total);            // 10 + 6 accumulated, not clobbered
        Assert.Equal(1, after2.failed);

        // Re-post ONLY Core with new numbers → replaces Core's suites, leaves Cli intact.
        await Post(Suite("Core.dll", "Core.T", passed: 20, failed: 0));
        var after3 = await Rollup();
        Assert.Equal(1, after3.reports);
        Assert.Equal(26, after3.total);            // 20 (new Core) + 6 (untouched Cli)
        Assert.Equal(1, after3.failed);            // Cli's failure survived
    }

    [SkippableFact]
    public async Task Raw_trx_posts_the_file_and_lands_suites()
    {
        Skip.IfNot(_fx.Available);
        var s = Guid.NewGuid().ToString("N")[..8];
        var (client, project, token) = await SeedProjectTokenAsync(s);

        var http = _fx.Factory!.CreateClient();
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var trx = await File.ReadAllTextAsync(FindTrx());
        var body = new StringContent(trx, Encoding.UTF8, "application/xml");
        var url = $"/ingest/test-results/raw?client={Uri.EscapeDataString(client)}&project={Uri.EscapeDataString(project)}&version=1.0.0&commitSha={s}rawtrx";

        var resp = await http.PostAsync(url, body);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var res = await resp.Content.ReadFromJsonAsync<TestResultsIngestResponse>();
        Assert.NotNull(res);
        Assert.True(res!.SuitesCount > 0);
        Assert.True(res.CasesCount > 0);

        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var report = await db.TestRunReports
            .SingleAsync(r => r.ComponentVersion!.CommitSha == $"{s}rawtrx");
        Assert.Equal("dotnet test (trx)", report.ToolName);
        Assert.True(report.TotalCount > 0);
    }

    [SkippableFact]
    public async Task Raw_cobertura_posts_the_file_and_lands_coverage()
    {
        Skip.IfNot(_fx.Available);
        var s = Guid.NewGuid().ToString("N")[..8];
        var (client, project, token) = await SeedProjectTokenAsync(s);

        var http = _fx.Factory!.CreateClient();
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        const string cobertura = """
        <coverage line-rate="0.8" branch-rate="0.5" lines-covered="8" lines-valid="10" branches-covered="1" branches-valid="2">
          <packages><package name="Pkg" line-rate="0.8"><classes>
            <class name="Pkg.C" filename="src/C.cs" line-rate="0.8"><lines>
              <line number="1" hits="1"/><line number="2" hits="0"/>
            </lines></class>
          </classes></package></packages>
        </coverage>
        """;
        var body = new StringContent(cobertura, Encoding.UTF8, "application/xml");
        var url = $"/ingest/coverage/raw?client={Uri.EscapeDataString(client)}&project={Uri.EscapeDataString(project)}&version=1.0.0&commitSha={s}rawcov";

        var resp = await http.PostAsync(url, body);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var report = await db.CoverageReports
            .SingleAsync(r => r.ComponentVersion!.CommitSha == $"{s}rawcov");
        Assert.Equal("cobertura", report.ToolName);
        Assert.Equal(80, report.SequenceCoverage);
        Assert.Equal(10, report.TotalSequences);
    }

    [SkippableFact]
    public async Task Raw_endpoint_rejects_an_unrecognised_document()
    {
        Skip.IfNot(_fx.Available);
        var s = Guid.NewGuid().ToString("N")[..8];
        var (client, project, token) = await SeedProjectTokenAsync(s);

        var http = _fx.Factory!.CreateClient();
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var body = new StringContent("<notAReport/>", Encoding.UTF8, "application/xml");
        var url = $"/ingest/test-results/raw?client={Uri.EscapeDataString(client)}&project={Uri.EscapeDataString(project)}&version=1.0.0";

        var resp = await http.PostAsync(url, body);
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);   // a well-formed but wrong-shape doc is the caller's error, not a 500
    }

    [SkippableFact]
    public async Task Evidence_for_one_commit_converges_on_one_build_despite_version_mismatch()
    {
        Skip.IfNot(_fx.Available);
        var s = Guid.NewGuid().ToString("N")[..8];
        var (client, project, token) = await SeedProjectTokenAsync(s);

        var http = _fx.Factory!.CreateClient();
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        // Producer A posts coverage under the FULL sha and its own version string.
        var fullSha = $"{s}dbe6bc1dbbbed01f7ef2f37804a9e9abcdef01";   // 40 hex-ish chars
        const string cobertura = """
        <coverage line-rate="0.9" lines-covered="9" lines-valid="10">
          <packages><package name="P"><classes>
            <class name="P.C" filename="C.cs"><lines><line number="1" hits="1"/></lines></class>
          </classes></package></packages>
        </coverage>
        """;
        var covResp = await http.PostAsync(
            $"/ingest/coverage/raw?client={Uri.EscapeDataString(client)}&project={Uri.EscapeDataString(project)}&version=0.0.0%2B{s}&commitSha={fullSha}",
            new StringContent(cobertura, Encoding.UTF8, "application/xml"));
        Assert.Equal(HttpStatusCode.OK, covResp.StatusCode);

        // Producer B posts test-results under the SHORT sha (a prefix) and a DIFFERENT version string —
        // the exact shape that used to split into a phantom build.
        var shortSha = fullSha[..8];
        var trx = await File.ReadAllTextAsync(FindTrx());
        var trxResp = await http.PostAsync(
            $"/ingest/test-results/raw?client={Uri.EscapeDataString(client)}&project={Uri.EscapeDataString(project)}&version=1.17.3&commitSha={shortSha}",
            new StringContent(trx, Encoding.UTF8, "application/xml"));
        Assert.Equal(HttpStatusCode.OK, trxResp.StatusCode);

        // Both must have landed on ONE build, and it should carry the full sha (converged upward).
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var builds = await db.ComponentVersions
            .Where(v => v.CommitSha != null && v.CommitSha.StartsWith(shortSha))
            .ToListAsync();
        var build = Assert.Single(builds);
        Assert.Equal(fullSha, build.CommitSha);   // the abbreviated post converged onto the full commit id
        Assert.True(await db.CoverageReports.AnyAsync(r => r.ComponentVersionId == build.Id));
        Assert.True(await db.TestRunReports.AnyAsync(r => r.ComponentVersionId == build.Id));
    }

    private static string FindTrx()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !Directory.Exists(Path.Combine(dir.FullName, "src"))) dir = dir.Parent;
        return Path.Combine(dir!.FullName, "tests", "Fixtures", "Ingest", "raw", "dotnet-test.trx");
    }
}
