using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Projects;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Integration.Tests;

// Portfolio ordering and blocking reasons against a real database (TFND-84).
//
// Ordering is the whole value of this screen, and it depends on data — a
// contract test cannot see whether the query actually sorts worst-first.
[Collection(DatabaseCollection.Name)]
public class PortfolioIntegrationTests
{
    private readonly DatabaseFixture _fx;

    public PortfolioIntegrationTests(DatabaseFixture fx) => _fx = fx;

    [SkippableFact]
    public async Task A_project_that_never_ingested_a_build_says_so_rather_than_scoring_zero()
    {
        Skip.IfNot(_fx.Available);

        var name = await SeedProjectAsync(withBuild: false);
        using var scope = _fx.Scope();
        var portfolio = scope.ServiceProvider.GetRequiredService<PortfolioQuery>();

        var row = (await portfolio.LoadAsync()).Single(r => r.ProjectName == name);

        Assert.Null(row.Score);
        Assert.Equal(ShipState.NoScan, row.Ship);
        Assert.Contains(row.Blocking, b => b.Contains("never ingested", StringComparison.OrdinalIgnoreCase));
    }

    [SkippableFact]
    public async Task An_unscanned_project_outranks_a_merely_bad_one()
    {
        Skip.IfNot(_fx.Available);

        // "A project with a green score and no recent scan is not healthy."
        // An unmeasured project is an unanswered question, and the design puts
        // it above a bad score rather than below it.
        var unscanned = await SeedProjectAsync(withBuild: false);
        var scanned = await SeedProjectAsync(withBuild: true);

        using var scope = _fx.Scope();
        var portfolio = scope.ServiceProvider.GetRequiredService<PortfolioQuery>();
        var rows = await portfolio.LoadAsync();

        var unscannedIndex = rows.ToList().FindIndex(r => r.ProjectName == unscanned);
        var scannedIndex = rows.ToList().FindIndex(r => r.ProjectName == scanned);

        Assert.True(unscannedIndex < scannedIndex,
            "a never-scanned project should sort above one that has been measured");
    }

    [SkippableFact]
    public async Task Blocking_reasons_are_prose_a_reader_can_act_on()
    {
        Skip.IfNot(_fx.Available);

        // "3 blocking" tells a security lead nothing. Every reason has to name
        // the thing that is wrong.
        var name = await SeedProjectAsync(withBuild: false);
        using var scope = _fx.Scope();
        var portfolio = scope.ServiceProvider.GetRequiredService<PortfolioQuery>();

        var row = (await portfolio.LoadAsync()).Single(r => r.ProjectName == name);

        Assert.All(row.Blocking, reason => Assert.True(reason.Length > 8, $"terse reason: '{reason}'"));
    }

    private async Task<string> SeedProjectAsync(bool withBuild)
    {
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);

        var suffix = Guid.NewGuid().ToString("N")[..8];
        var client = new Client { Name = $"pf-client-{suffix}" };
        var project = new Project { ClientId = client.Id, Name = $"pf-project-{suffix}" };
        db.Clients.Add(client);
        db.Projects.Add(project);

        if (withBuild)
        {
            var component = new Component { ProjectId = project.Id, Name = $"pf-component-{suffix}" };
            db.Components.Add(component);
            db.ComponentVersions.Add(new ComponentVersion
            {
                ComponentId = component.Id,
                VersionString = "0.1.0",
                CommitSha = suffix + "aaaaaa",
            });
        }

        await db.SaveChangesAsync();
        return project.Name;
    }
}
