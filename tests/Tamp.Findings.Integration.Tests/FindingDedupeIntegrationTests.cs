using Tamp.Findings.Application.Risk;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Integration.Tests;

[Collection(DatabaseCollection.Name)]
public class FindingDedupeIntegrationTests
{
    private readonly DatabaseFixture _fx;
    public FindingDedupeIntegrationTests(DatabaseFixture fx) => _fx = fx;

    private async Task<(Guid cv, Guid sonar, Guid roslyn)> SeedAsync(FindingStatus sonarStatus)
    {
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var s = Guid.NewGuid().ToString("N")[..8];
        var client = new Client { Name = $"dd-client-{s}" };
        var project = new Project { ClientId = client.Id, Name = $"dd-project-{s}" };
        var cv = new ComponentVersion { ProjectId = project.Id, VersionString = "1.0.0", CommitSha = $"{s}dd" };
        Finding F(ScannerKind k, string rule, FindingStatus st) => new()
        {
            ComponentVersionId = cv.Id, Hash = Guid.NewGuid().ToString("N"), Scanner = k, RuleId = rule,
            Title = "t", FilePath = "src/A.cs", Line = 10, Severity = Severity.Medium, Status = st,
        };
        var sonar = F(ScannerKind.SonarQube, "csharpsquid:S2325", sonarStatus);
        var roslyn = F(ScannerKind.Roslyn, "S2325", FindingStatus.Open);
        db.Clients.Add(client); db.Projects.Add(project); db.ComponentVersions.Add(cv);
        db.Findings.AddRange(sonar, roslyn);
        await db.SaveChangesAsync();
        return (cv.Id, sonar.Id, roslyn.Id);
    }

    [SkippableFact]
    public async Task An_open_sonar_row_collapses_its_roslyn_twin()
    {
        Skip.IfNot(_fx.Available);
        var (cv, _, roslyn) = await SeedAsync(FindingStatus.Open);
        using var scope = _fx.Scope();
        var dupes = await FindingDedupe.DuplicateIdsAsync(_fx.Db(scope), [cv], default);
        Assert.Contains(roslyn, dupes);
    }

    [SkippableFact]
    public async Task A_closed_sonar_row_does_not_hide_a_live_roslyn_twin()
    {
        Skip.IfNot(_fx.Available);
        var (cv, _, roslyn) = await SeedAsync(FindingStatus.Accepted);
        using var scope = _fx.Scope();
        var dupes = await FindingDedupe.DuplicateIdsAsync(_fx.Db(scope), [cv], default);
        Assert.DoesNotContain(roslyn, dupes);
    }
}
