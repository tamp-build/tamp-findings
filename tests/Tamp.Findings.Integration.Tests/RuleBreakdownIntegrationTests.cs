using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Explorer;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Integration.Tests;

// The per-rule breakdown (TFND-18).
//
// The explorer groups by path, which answers "which files are bad". It does not
// answer "what is wrong with this codebase" — and with SonarAnalyzer's ~470
// rules plus Roslynator's ~500, a severity count cannot tell eleven S2094s from
// four S6966s. One is "delete some empty classes"; the other is a real API
// misuse, and they are two completely different pieces of work.
[Collection(DatabaseCollection.Name)]
public class RuleBreakdownIntegrationTests
{
    private readonly DatabaseFixture _fx;

    public RuleBreakdownIntegrationTests(DatabaseFixture fx) => _fx = fx;

    [SkippableFact]
    public async Task Findings_collapse_into_one_row_per_rule()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var rules = scope.ServiceProvider.GetRequiredService<RuleBreakdownQuery>();

        var rows = await rules.ByRuleAsync(world.ProjectId, world.Sha, ScannerKinds.Sast);

        Assert.Equal(11, rows.Single(r => r.RuleId == "S2094").Count);
        Assert.Equal(4, rows.Single(r => r.RuleId == "S6966").Count);
    }

    [SkippableFact]
    public async Task The_worst_rule_sorts_first_even_when_a_nit_is_more_common()
    {
        Skip.IfNot(_fx.Available);

        // Ordering by count alone would put 200 style nits above a single
        // critical, which is the exact failure mode of a severity-only count in
        // the other direction.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var rules = scope.ServiceProvider.GetRequiredService<RuleBreakdownQuery>();

        var rows = await rules.ByRuleAsync(world.ProjectId, world.Sha, ScannerKinds.Sast);

        Assert.Equal("S5766", rows[0].RuleId);
        Assert.Equal(Severity.Critical, rows[0].WorstSeverity);
        Assert.Equal(1, rows[0].Count);
    }

    [SkippableFact]
    public async Task A_rule_carries_its_own_title_rather_than_only_an_id()
    {
        Skip.IfNot(_fx.Available);

        // Nobody knows what S6966 is, and the scanner already told us.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var rules = scope.ServiceProvider.GetRequiredService<RuleBreakdownQuery>();

        var row = (await rules.ByRuleAsync(world.ProjectId, world.Sha, ScannerKinds.Sast))
            .Single(r => r.RuleId == "S6966");

        Assert.Equal("Awaitable method should be used", row.Title);
    }

    [SkippableFact]
    public async Task A_rule_concentrated_in_one_file_is_flagged_as_such()
    {
        Skip.IfNot(_fx.Available);

        // It changes what the fix is: 40 hits in one file is usually one bad
        // pattern to correct once, the same count across 40 files is a habit.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var rules = scope.ServiceProvider.GetRequiredService<RuleBreakdownQuery>();

        var rows = await rules.ByRuleAsync(world.ProjectId, world.Sha, ScannerKinds.Sast);

        var concentrated = rows.Single(r => r.RuleId == "S2094");
        Assert.True(concentrated.Concentrated);
        Assert.Equal("src/Api/Big.cs", concentrated.TopFilePath);
        Assert.Equal(10, concentrated.TopFileCount);

        // Spread evenly across four files — not concentrated.
        Assert.False(rows.Single(r => r.RuleId == "S6966").Concentrated);
    }

    [SkippableFact]
    public async Task A_rule_counts_the_files_it_spans()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var rules = scope.ServiceProvider.GetRequiredService<RuleBreakdownQuery>();

        var row = (await rules.ByRuleAsync(world.ProjectId, world.Sha, ScannerKinds.Sast))
            .Single(r => r.RuleId == "S6966");

        Assert.Equal(4, row.FileCount);
    }

    [SkippableFact]
    public async Task Scanners_outside_the_requested_set_are_excluded()
    {
        Skip.IfNot(_fx.Available);

        // Mixing a Roslyn rule and a ZAP alert in one ranked list invites
        // comparing counts that mean different things.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var rules = scope.ServiceProvider.GetRequiredService<RuleBreakdownQuery>();

        var sast = await rules.ByRuleAsync(world.ProjectId, world.Sha, ScannerKinds.Sast);
        var dast = await rules.ByRuleAsync(world.ProjectId, world.Sha, ScannerKinds.Dast);

        Assert.DoesNotContain(sast, r => r.RuleId == "ZAP-10202");
        Assert.Contains(dast, r => r.RuleId == "ZAP-10202");
    }

    [SkippableFact]
    public async Task Closed_findings_do_not_appear()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var rules = scope.ServiceProvider.GetRequiredService<RuleBreakdownQuery>();

        var rows = await rules.ByRuleAsync(world.ProjectId, world.Sha, ScannerKinds.Sast);

        Assert.DoesNotContain(rows, r => r.RuleId == "S1118");
    }

    [SkippableFact]
    public async Task Drilling_into_a_rule_lists_every_occurrence_by_file()
    {
        Skip.IfNot(_fx.Available);

        // Within one rule the severity is usually constant, so severity
        // ordering would be arbitrary while file ordering lets a reader work
        // through it.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var findings = scope.ServiceProvider.GetRequiredService<FindingsExplorerQuery>();

        var rows = await findings.ByRuleDetailAsync(
            world.ProjectId, world.Sha, ScannerKinds.Sast, "S6966");

        Assert.Equal(4, rows.Count);
        Assert.True(
            string.CompareOrdinal(rows[0].FilePath, rows[^1].FilePath) <= 0,
            "occurrences should be ordered by file path");
    }

    [SkippableFact]
    public async Task A_rule_that_fires_nowhere_returns_nothing_rather_than_throwing()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var findings = scope.ServiceProvider.GetRequiredService<FindingsExplorerQuery>();

        Assert.Empty(await findings.ByRuleDetailAsync(
            world.ProjectId, world.Sha, ScannerKinds.Sast, "NOT-A-RULE"));
    }

    // ---- Seed ---------------------------------------------------------------

    private sealed record World(Guid ProjectId, string Sha);

    private async Task<World> SeedAsync()
    {
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);

        var suffix = Guid.NewGuid().ToString("N")[..8];
        var sha = suffix + "111111";

        var client = new Client { Name = $"rule-client-{suffix}" };
        var project = new Project { ClientId = client.Id, Name = $"rule-project-{suffix}" };
        var component = new Component { ProjectId = project.Id, Name = $"rule-component-{suffix}" };
        var version = new ComponentVersion
        {
            ComponentId = component.Id, VersionString = "1.0.0", CommitSha = sha,
        };

        db.Clients.Add(client);
        db.Projects.Add(project);
        db.Components.Add(component);
        db.ComponentVersions.Add(version);

        void Finding(ScannerKind scanner, string ruleId, string title, Severity severity,
                     string? path, FindingStatus status = FindingStatus.Open) =>
            db.Findings.Add(new Finding
            {
                ComponentVersionId = version.Id,
                Hash = Guid.NewGuid().ToString("N"),
                Scanner = scanner,
                RuleId = ruleId,
                Severity = severity,
                Title = title,
                FilePath = path,
                Status = status,
            });

        // Eleven S2094s, ten of them in one file — the concentrated case.
        for (var i = 0; i < 10; i++)
            Finding(ScannerKind.Roslyn, "S2094", "Class should not be empty", Severity.Low, "src/Api/Big.cs");
        Finding(ScannerKind.Roslyn, "S2094", "Class should not be empty", Severity.Low, "src/Api/Other.cs");

        // Four S6966s across four files — the habit case.
        foreach (var file in new[] { "src/A.cs", "src/B.cs", "src/C.cs", "src/D.cs" })
            Finding(ScannerKind.Roslyn, "S6966", "Awaitable method should be used", Severity.Medium, file);

        // One critical, which must still sort above both.
        Finding(ScannerKind.Roslyn, "S5766", "Deserialization should not be vulnerable",
                Severity.Critical, "src/Api/Deser.cs");

        // Closed — must not appear.
        Finding(ScannerKind.Roslyn, "S1118", "Utility classes should not have public constructors",
                Severity.Low, "src/Api/Util.cs", FindingStatus.Fixed);

        // A different class of scanner entirely.
        Finding(ScannerKind.Zap, "ZAP-10202", "Absence of anti-CSRF tokens", Severity.Medium,
                "https://app.test/login");

        await db.SaveChangesAsync();
        return new World(project.Id, sha);
    }
}
