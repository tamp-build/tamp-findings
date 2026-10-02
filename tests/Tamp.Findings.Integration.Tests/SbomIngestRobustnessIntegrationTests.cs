using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Ingest;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Integration.Tests;

// TFND-168: components[].vulnerabilities is optional on the wire; omitting it must not 500.
[Collection(DatabaseCollection.Name)]
public class SbomIngestRobustnessIntegrationTests
{
    private readonly DatabaseFixture _fx;
    public SbomIngestRobustnessIntegrationTests(DatabaseFixture fx) => _fx = fx;

    [SkippableFact]
    public async Task A_component_that_omits_vulnerabilities_ingests_as_having_none()
    {
        Skip.IfNot(_fx.Available);
        var s = Guid.NewGuid().ToString("N")[..8];
        Guid projectId, userId; string clientName, projectName;
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            var user = new User { Login = $"sb-{s}", DisplayName = "sb", Email = $"sb{s}@e.test", IsApproved = true };
            var client = new Client { Name = $"sb-{s}" };
            var project = new Project { ClientId = client.Id, Name = $"sbp-{s}" };
            db.Users.Add(user); db.Clients.Add(client); db.Projects.Add(project);
            await db.SaveChangesAsync();
            (projectId, userId, clientName, projectName) = (project.Id, user.Id, client.Name, project.Name);
        }
        string token;
        using (var scope = _fx.Scope())
            token = (await scope.ServiceProvider.GetRequiredService<IngestTokenService>()
                .MintProjectTokenAsync(projectId, "sb-tok", userId, default)).Plaintext;

        var http = _fx.Factory!.CreateClient();
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        var json = $$"""
            {"client":"{{clientName}}","project":"{{projectName}}","version":"1.0.0","commitSha":"{{s}}cafe",
             "components":[{"purl":"pkg:nuget/Foo@1.0.0","name":"Foo","version":"1.0.0"}],
             "dependencies":[]}
            """;

        var resp = await http.PostAsync("/ingest/sbom", new StringContent(json, Encoding.UTF8, "application/json"));

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        using var scope2 = _fx.Scope();
        var db2 = _fx.Db(scope2);
        var comp = await db2.SbomComponents.Include(c => c.Vulnerabilities)
            .SingleAsync(c => c.Purl == "pkg:nuget/Foo@1.0.0"
                && db2.SbomSnapshots.Any(sn => sn.Id == c.SbomSnapshotId
                    && db2.ComponentVersions.Any(v => v.Id == sn.ComponentVersionId && v.ProjectId == projectId)));
        Assert.Empty(comp.Vulnerabilities);
    }
}
