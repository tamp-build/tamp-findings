using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Api.Contracts;
using Tamp.Findings.Application.Ingest;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Integration.Tests;

// The test-results ingest stores producer-supplied names in bounded columns. A theory case whose display name
// carries long data (or a deeply generic class name) once made the whole ingest 500 on 22001 and lost every
// result for the build. It must clamp instead.
[Collection(DatabaseCollection.Name)]
public class TestResultsLongNamesIntegrationTests
{
    private readonly DatabaseFixture _fx;
    public TestResultsLongNamesIntegrationTests(DatabaseFixture fx) => _fx = fx;

    [SkippableFact]
    public async Task Oversized_assembly_class_and_case_names_are_clamped_not_a_500()
    {
        Skip.IfNot(_fx.Available);
        var s = Guid.NewGuid().ToString("N")[..8];
        Guid projectId, userId; string clientName, projectName;
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            var user = new User { Login = $"tl-{s}", DisplayName = "tl", Email = $"tl{s}@e.test", IsApproved = true };
            var client = new Client { Name = $"tl-client-{s}" };
            var project = new Project { ClientId = client.Id, Name = $"tl-project-{s}" };
            db.Users.Add(user); db.Clients.Add(client); db.Projects.Add(project);
            await db.SaveChangesAsync();
            (projectId, userId, clientName, projectName) = (project.Id, user.Id, client.Name, project.Name);
        }
        string token;
        using (var scope = _fx.Scope())
            token = (await scope.ServiceProvider.GetRequiredService<IngestTokenService>()
                .MintProjectTokenAsync(projectId, "tl-tok", userId, default)).Plaintext;
        var http = _fx.Factory!.CreateClient();
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var hugeCase = "Theory(data: \"" + new string('x', 3000) + "\")";
        var hugeClass = "Ns." + new string('G', 2000);
        var hugeAssembly = new string('A', 900) + ".Tests";
        var req = new TestResultsIngestRequest(
            clientName, projectName, null, null, null, "1.0.0", $"{s}tlsha", null, null, null, "xunit", "2",
            2, 2, 0, 0, 0, 5, DateTimeOffset.UtcNow.AddSeconds(-5), DateTimeOffset.UtcNow,
            [
                new TestSuiteRequestDto(hugeAssembly, hugeClass, 2, 2, 0, 0, 0, 5,
                [
                    new TestCaseRequestDto(hugeCase, Tamp.Findings.Domain.Values.TestOutcome.Passed, 1, null, null),
                    new TestCaseRequestDto("short", Tamp.Findings.Domain.Values.TestOutcome.Passed, 1, null, null),
                ]),
            ]);

        var resp = await http.PostAsJsonAsync("/ingest/test-results", req);

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        using var scope2 = _fx.Scope();
        var db2 = _fx.Db(scope2);
        var suite = await db2.TestSuiteResults.Include(x => x.Cases)
            .SingleAsync(x => db2.TestRunReports.Any(r => r.Id == x.TestRunReportId
                && db2.ComponentVersions.Any(v => v.Id == r.ComponentVersionId && v.ProjectId == projectId)));
        Assert.Equal(512, suite.AssemblyName.Length);
        Assert.Equal(1024, suite.ClassName.Length);
        Assert.Equal(2, suite.Cases.Count);
        Assert.Contains(suite.Cases, c => c.Name.Length == 1024 && c.Name.EndsWith("…"));
        Assert.Contains(suite.Cases, c => c.Name == "short");
    }
}
