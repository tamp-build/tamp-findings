using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Risk;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Risk;

namespace Tamp.Findings.Integration.Tests;

// TFND-211 / CM-8(3): a banned component in a build's SBOM is counted into the gate inputs; the list is
// admin-edited and audited; version-narrowed and deactivated entries do not match.
[Collection(DatabaseCollection.Name)]
public class UnauthorizedComponentIntegrationTests
{
    private readonly DatabaseFixture _fx;
    public UnauthorizedComponentIntegrationTests(DatabaseFixture fx) => _fx = fx;

    private sealed record World(Guid ProjectId, Guid CvId, Guid UserId, string Login, string Suffix);

    private async Task<World> SeedAsync()
    {
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var s = Guid.NewGuid().ToString("N")[..8];
        var user = new User { Login = $"uc-{s}", DisplayName = "uc", Email = $"uc{s}@e.test", IsApproved = true };
        var client = new Client { Name = $"uc-client-{s}" };
        var project = new Project { ClientId = client.Id, Name = $"uc-project-{s}" };
        var cv = new ComponentVersion { ProjectId = project.Id, VersionString = "1.0.0", CommitSha = $"{s}uc" };
        var snap = new SbomSnapshot { ComponentVersionId = cv.Id, ToolName = "syft", SpecVersion = "1.5" };
        db.Users.Add(user); db.Clients.Add(client); db.Projects.Add(project); db.ComponentVersions.Add(cv); db.SbomSnapshots.Add(snap);
        db.SbomComponents.AddRange(
            new SbomComponent { SbomSnapshotId = snap.Id, Purl = $"pkg:nuget/Evil.{s}@2.0.0", Name = $"Evil.{s}", Version = "2.0.0" },
            new SbomComponent { SbomSnapshotId = snap.Id, Purl = $"pkg:nuget/Fine.{s}@1.0.0", Name = $"Fine.{s}", Version = "1.0.0" });
        await db.SaveChangesAsync();
        return new World(project.Id, cv.Id, user.Id, user.Login, s);
    }

    private Principal Admin(World w) => Principal.For(w.UserId, w.Login, isAdmin: true, []);

    private async Task<int> UnauthorizedCountAsync(World w)
    {
        using var scope = _fx.Scope();
        var builder = scope.ServiceProvider.GetRequiredService<RiskInputsBuilder>();
        var policy = (await scope.ServiceProvider.GetRequiredService<ScoringPolicyResolver>().ForProjectAsync(w.ProjectId)).Config;
        var inputs = await builder.BuildAsync([w.CvId], policy, w.ProjectId, default);
        return inputs.UnauthorizedComponents;
    }

    [SkippableFact]
    public async Task A_banned_package_in_the_sbom_is_counted_and_an_unlisted_one_is_not()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        Assert.Equal(0, await UnauthorizedCountAsync(w));

        using (var scope = _fx.Scope())
        {
            var r = await scope.ServiceProvider.GetRequiredService<BannedComponentService>()
                .AddAsync(Admin(w), $"pkg:nuget/EVIL.{w.Suffix}", null, "typosquat");
            Assert.True(r.Success);
        }

        Assert.Equal(1, await UnauthorizedCountAsync(w));   // purl match is case-insensitive and version-less
    }

    [SkippableFact]
    public async Task A_version_narrowed_entry_only_matches_those_versions()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        using (var scope = _fx.Scope())
            await scope.ServiceProvider.GetRequiredService<BannedComponentService>()
                .AddAsync(Admin(w), $"pkg:nuget/Evil.{w.Suffix}", ["1.0.0"], "only 1.0.0 is bad");
        Assert.Equal(0, await UnauthorizedCountAsync(w));   // the SBOM has 2.0.0

        using (var scope = _fx.Scope())
            await scope.ServiceProvider.GetRequiredService<BannedComponentService>()
                .AddAsync(Admin(w), $"pkg:nuget/Evil.{w.Suffix}", ["1.0.0", "2.0.0"], "now includes 2.0.0");
        Assert.Equal(1, await UnauthorizedCountAsync(w));
    }

    [SkippableFact]
    public async Task Removing_an_entry_stops_it_matching_and_only_admins_can_edit_the_list()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        Guid id;
        using (var scope = _fx.Scope())
            id = (await scope.ServiceProvider.GetRequiredService<BannedComponentService>()
                .AddAsync(Admin(w), $"pkg:nuget/Evil.{w.Suffix}", null, "bad")).Value!.Id;
        Assert.Equal(1, await UnauthorizedCountAsync(w));

        using (var scope = _fx.Scope())
        {
            var svc = scope.ServiceProvider.GetRequiredService<BannedComponentService>();
            var viewer = Principal.For(w.UserId, w.Login, isAdmin: false, []);
            Assert.True((await svc.RemoveAsync(viewer, id)).WasDenied);
            Assert.True((await svc.AddAsync(viewer, "pkg:npm/x", null, "r")).WasDenied);
            Assert.True((await svc.RemoveAsync(Admin(w), id)).Success);
        }
        Assert.Equal(0, await UnauthorizedCountAsync(w));
    }

    [SkippableFact]
    public async Task A_deactivated_feed_entry_does_not_match()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        Guid id;
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            var row = new BannedComponent
            {
                Purl = $"pkg:nuget/evil.{w.Suffix}", Source = "osv-malicious", SourceId = $"MAL-{w.Suffix}",
                Kind = BannedComponentKind.Malicious, Reason = "feed",
            };
            db.BannedComponents.Add(row);
            await db.SaveChangesAsync();
            id = row.Id;
        }
        Assert.Equal(1, await UnauthorizedCountAsync(w));

        using (var scope = _fx.Scope())
            Assert.True((await scope.ServiceProvider.GetRequiredService<BannedComponentService>().RemoveAsync(Admin(w), id)).Success);

        Assert.Equal(0, await UnauthorizedCountAsync(w));
        using var scope2 = _fx.Scope();
        Assert.True(await _fx.Db(scope2).BannedComponents.AnyAsync(b => b.Id == id && !b.Active));   // kept, so a re-sync can't resurrect it
    }

    [SkippableFact]
    public async Task Adding_requires_a_valid_purl_and_a_reason()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        using var scope = _fx.Scope();
        var svc = scope.ServiceProvider.GetRequiredService<BannedComponentService>();

        Assert.False((await svc.AddAsync(Admin(w), "left-pad", null, "reason")).Success);
        Assert.False((await svc.AddAsync(Admin(w), "pkg:npm/left-pad", null, "  ")).Success);
    }
}
