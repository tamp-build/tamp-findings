using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Api.Services;
using Tamp.Findings.Application.Ingest;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Integration.Tests;

// TFND-229: /sbom-components/enrich-versions accepted any valid ingest token and, without a snapshotId,
// enriched every component of every tenant. snapshotId is now required and must belong to the token's scope.
[Collection(DatabaseCollection.Name)]
public class SbomEnrichScopeTests
{
    private readonly DatabaseFixture _fx;
    public SbomEnrichScopeTests(DatabaseFixture fx) => _fx = fx;

    private sealed record Tenant(Guid ClientId, Guid ProjectId, Guid SnapshotId, Guid UserId, Guid ComponentId);

    // A client, a project, a build with an SBOM snapshot holding one nuget component that has NO latest version yet.
    private async Task<Tenant> SeedTenantAsync()
    {
        var s = ApiBSupport.Suffix();
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var user = new User { Login = $"ens-{s}", DisplayName = "e", Email = $"e{s}@e.test", IsApproved = true };
        var client = new Client { Name = $"ens-c-{s}" };
        var project = new Project { ClientId = client.Id, Name = $"ens-p-{s}" };
        db.Users.Add(user); db.Clients.Add(client); db.Projects.Add(project);
        var cv = new ComponentVersion { ProjectId = project.Id, VersionString = "1.0.0", CommitSha = $"{s}en" };
        var snap = new SbomSnapshot { ComponentVersionId = cv.Id };
        var comp = new SbomComponent { SbomSnapshotId = snap.Id, Purl = $"pkg:nuget/Ens.{s}@1.0.0", Name = $"Ens.{s}", Version = "1.0.0" };
        db.ComponentVersions.Add(cv); db.SbomSnapshots.Add(snap); db.SbomComponents.Add(comp);
        await db.SaveChangesAsync();
        return new Tenant(client.Id, project.Id, snap.Id, user.Id, comp.Id);
    }

    private HttpClient FakeRegistryClient(string token)
    {
        var handler = new ApiBFakeRegistryHandler();
        return _fx.Factory!.WithWebHostBuilder(b => b.ConfigureTestServices(services =>
            services.AddHttpClient("registries").ConfigurePrimaryHttpMessageHandler(() => handler))).Bearer(token);
    }

    private async Task<string> ProjectTokenAsync(Tenant t)
    {
        using var scope = _fx.Scope();
        return (await scope.ServiceProvider.GetRequiredService<IngestTokenService>().MintProjectTokenAsync(t.ProjectId, "ens", t.UserId, default)).Plaintext;
    }

    private async Task<string> ClientTokenAsync(Tenant t)
    {
        using var scope = _fx.Scope();
        return (await scope.ServiceProvider.GetRequiredService<IngestTokenService>().MintClientTokenAsync(t.ClientId, "ens", t.UserId, default)).Plaintext;
    }

    private async Task<DateTimeOffset?> EnrichedAtAsync(Guid componentId)
    {
        using var scope = _fx.Scope();
        return (await _fx.Db(scope).SbomComponents.AsNoTracking().FirstAsync(c => c.Id == componentId)).EnrichedAt;
    }

    [SkippableFact]
    public async Task A_missing_snapshotId_is_a_400_and_nothing_is_enriched()
    {
        Skip.IfNot(_fx.Available);
        var t = await SeedTenantAsync();

        var resp = await FakeRegistryClient(await ProjectTokenAsync(t)).PostAsync("/sbom-components/enrich-versions", null);

        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
        Assert.Null(await EnrichedAtAsync(t.ComponentId));
    }

    [SkippableFact]
    public async Task A_project_token_cannot_enrich_another_projects_snapshot_and_gets_a_404()
    {
        Skip.IfNot(_fx.Available);
        var mine = await SeedTenantAsync();
        var theirs = await SeedTenantAsync();

        var resp = await FakeRegistryClient(await ProjectTokenAsync(mine))
            .PostAsync($"/sbom-components/enrich-versions?snapshotId={theirs.SnapshotId}", null);

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
        Assert.Null(await EnrichedAtAsync(theirs.ComponentId));   // the other tenant's data was not touched
    }

    [SkippableFact]
    public async Task A_project_token_can_enrich_its_own_snapshot()
    {
        Skip.IfNot(_fx.Available);
        var t = await SeedTenantAsync();

        var resp = await FakeRegistryClient(await ProjectTokenAsync(t))
            .PostAsync($"/sbom-components/enrich-versions?snapshotId={t.SnapshotId}", null);

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var result = (await resp.Content.ReadFromJsonAsync<SbomEnrichmentService.Result>(ApiBSupport.Json))!;
        Assert.Equal(1, result.Checked);
    }

    [SkippableFact]
    public async Task A_client_token_reaches_projects_under_its_client_but_not_another_clients()
    {
        Skip.IfNot(_fx.Available);
        var mine = await SeedTenantAsync();
        var theirs = await SeedTenantAsync();
        var http = FakeRegistryClient(await ClientTokenAsync(mine));

        var own = await http.PostAsync($"/sbom-components/enrich-versions?snapshotId={mine.SnapshotId}", null);
        var other = await http.PostAsync($"/sbom-components/enrich-versions?snapshotId={theirs.SnapshotId}", null);

        Assert.Equal(HttpStatusCode.OK, own.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, other.StatusCode);
        Assert.Null(await EnrichedAtAsync(theirs.ComponentId));
    }
}
