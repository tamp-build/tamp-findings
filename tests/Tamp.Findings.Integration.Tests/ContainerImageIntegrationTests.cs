using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Projects;
using Tamp.Findings.Application.Risk;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Risk;

namespace Tamp.Findings.Integration.Tests;

// Base-image age end to end (TFND-134).
//
// The ingest and gate halves are unit-tested; what needs a database is the part
// in between — that an inspected image reaches RiskInputs, that the WORST base
// across a commit's builds is the one that counts, and that an uninspected
// build leaves the gate Unknown rather than passing.
[Collection(DatabaseCollection.Name)]
public class ContainerImageIntegrationTests
{
    private readonly DatabaseFixture _fx;

    public ContainerImageIntegrationTests(DatabaseFixture fx) => _fx = fx;

    [SkippableFact]
    public async Task An_inspected_base_image_reaches_the_risk_inputs()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync(baseAgeDays: 200);
        using var scope = _fx.Scope();
        var builder = scope.ServiceProvider.GetRequiredService<RiskInputsBuilder>();

        var inputs = await builder.BuildAsync(
            [world.VersionId], RiskPolicyDefaults.BuildTampFederalV1(), world.ProjectId, default);

        Assert.True(inputs.RanImageInspect);
        Assert.Equal(200, inputs.BaseImageAgeDays);
    }

    [SkippableFact]
    public async Task A_build_with_no_image_leaves_the_gate_unknown_rather_than_passing()
    {
        Skip.IfNot(_fx.Available);

        // The rule this product is built on: a count of zero means nobody
        // looked. An unmeasured base image is not a fresh one.
        var world = await SeedAsync(baseAgeDays: null, inspect: false);
        using var scope = _fx.Scope();
        var builder = scope.ServiceProvider.GetRequiredService<RiskInputsBuilder>();

        var inputs = await builder.BuildAsync(
            [world.VersionId], RiskPolicyDefaults.BuildTampFederalV1(), world.ProjectId, default);

        Assert.False(inputs.RanImageInspect);

        var gates = ProjectGatesDefaults.Empty();
        gates.Gates[GateKeys.BaseImageAge] = new GateConfig { Enabled = true };

        var gate = GateEvaluator.Evaluate(gates, inputs, 0, null, null)
            .Results.Single(g => g.Key == GateKeys.BaseImageAge);

        Assert.Equal(GateVerdict.Unknown, gate.Verdict);
    }

    [SkippableFact]
    public async Task An_inspected_image_with_no_identifiable_base_is_still_unknown()
    {
        Skip.IfNot(_fx.Available);

        // The common case: the pipeline is wired up, but the OCI annotation
        // that names the base image is absent. "We looked and cannot tell" is
        // not "it is fine".
        var world = await SeedAsync(baseAgeDays: null, inspect: true);
        using var scope = _fx.Scope();
        var builder = scope.ServiceProvider.GetRequiredService<RiskInputsBuilder>();

        var inputs = await builder.BuildAsync(
            [world.VersionId], RiskPolicyDefaults.BuildTampFederalV1(), world.ProjectId, default);

        Assert.True(inputs.RanImageInspect);
        Assert.Null(inputs.BaseImageAgeDays);
    }

    [SkippableFact]
    public async Task The_worst_base_across_a_commits_builds_is_the_one_that_counts()
    {
        Skip.IfNot(_fx.Available);

        // A commit can produce several builds distinguished by flavour. One
        // shipping on a two-year-old base is a fact an average would dissolve,
        // and it is the one somebody has to act on.
        var world = await SeedAsync(baseAgeDays: 30, secondBuildBaseAgeDays: 700);
        using var scope = _fx.Scope();
        var builder = scope.ServiceProvider.GetRequiredService<RiskInputsBuilder>();

        var inputs = await builder.BuildAsync(
            [world.VersionId, world.SecondVersionId!.Value],
            RiskPolicyDefaults.BuildTampFederalV1(), world.ProjectId, default);

        Assert.Equal(700, inputs.BaseImageAgeDays);
    }

    [SkippableFact]
    public async Task Re_inspecting_a_build_replaces_rather_than_accumulates()
    {
        Skip.IfNot(_fx.Available);

        // Two rows would leave two answers to "how old is the base image", and
        // the score would depend on which one a query happened to pick. The
        // unique index is what stops that; this asserts it.
        var world = await SeedAsync(baseAgeDays: 200);
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);

        var duplicate = new ContainerImage
        {
            ComponentVersionId = world.VersionId,
            Reference = "registry.example/app:again",
        };
        db.ContainerImages.Add(duplicate);

        await Assert.ThrowsAnyAsync<DbUpdateException>(() => db.SaveChangesAsync());
    }

    [SkippableFact]
    public async Task The_project_hub_surfaces_the_image()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync(baseAgeDays: 400);
        using var scope = _fx.Scope();
        var hub = scope.ServiceProvider.GetRequiredService<ProjectHubQuery>();

        var project = await hub.ResolveAsync(
            world.ClientName, world.ProjectName,
            Application.Authorization.VisibleSet.Everything);

        var data = await hub.LoadAsync(project!, null);

        var image = Assert.Single(data!.Images);
        Assert.Equal(400, image.BaseImageAgeInDays);
        Assert.Equal("mcr.microsoft.com/dotnet/aspnet:10.0-alpine", image.BaseImageReference);
    }

    // ---- Seed ----------------------------------------------------------------

    private sealed record World(
        Guid ProjectId, Guid VersionId, Guid? SecondVersionId,
        string ClientName, string ProjectName);

    private async Task<World> SeedAsync(
        int? baseAgeDays, bool inspect = true, int? secondBuildBaseAgeDays = null)
    {
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);

        var suffix = Guid.NewGuid().ToString("N")[..8];
        var inspectedAt = DateTimeOffset.UtcNow;

        var client = new Client { Name = $"img-client-{suffix}" };
        var project = new Project { ClientId = client.Id, Name = $"img-project-{suffix}" };
        var component = new Component { ProjectId = project.Id, Name = "api" };
        var version = new ComponentVersion
        {
            ComponentId = component.Id, VersionString = "1.0.0", CommitSha = $"{suffix}aaaaaa",
        };

        db.Clients.Add(client);
        db.Projects.Add(project);
        db.Components.Add(component);
        db.ComponentVersions.Add(version);

        if (inspect)
        {
            db.ContainerImages.Add(Image(version.Id, baseAgeDays, inspectedAt));
        }

        Guid? secondId = null;
        if (secondBuildBaseAgeDays is { } secondAge)
        {
            var web = new Component { ProjectId = project.Id, Name = "web" };
            var secondVersion = new ComponentVersion
            {
                ComponentId = web.Id, VersionString = "1.0.0", CommitSha = $"{suffix}aaaaaa",
            };

            db.Components.Add(web);
            db.ComponentVersions.Add(secondVersion);
            db.ContainerImages.Add(Image(secondVersion.Id, secondAge, inspectedAt));

            secondId = secondVersion.Id;
        }

        await db.SaveChangesAsync();

        return new World(project.Id, version.Id, secondId, client.Name, project.Name);
    }

    private static ContainerImage Image(Guid versionId, int? baseAgeDays, DateTimeOffset inspectedAt) =>
        new()
        {
            ComponentVersionId = versionId,
            Reference = "registry.example/app:1.0.0",
            Digest = "sha256:deadbeef",
            CreatedAt = inspectedAt,
            OsFamily = "alpine",
            OsVersion = "3.21",
            // A base reference with no date is the common shape, so the "no
            // identifiable base" case seeds neither.
            BaseImageReference = baseAgeDays is null ? null : "mcr.microsoft.com/dotnet/aspnet:10.0-alpine",
            BaseImageCreatedAt = baseAgeDays is { } days ? inspectedAt.AddDays(-days) : null,
            InspectedAt = inspectedAt,
        };
}
