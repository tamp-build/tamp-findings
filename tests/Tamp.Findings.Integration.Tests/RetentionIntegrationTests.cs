using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Retention;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Integration.Tests;

// Enforcing the retention window (TFND-13 / F12.4).
//
// This deletes evidence, permanently, from a product whose job is being able to
// show what was true. So most of what these assert is what the sweep REFUSES to
// delete — the safety rails are the feature, and a retention job with a bug in
// them is not recoverable from.
[Collection(DatabaseCollection.Name)]
public class RetentionIntegrationTests : IAsyncLifetime
{
    private readonly DatabaseFixture _fx;

    public RetentionIntegrationTests(DatabaseFixture fx) => _fx = fx;

    public Task InitializeAsync() => Task.CompletedTask;

    /// <summary>
    /// Put the retention window back to "keep everything".
    ///
    /// InstanceSettings is a SINGLETON row shared by the whole test database,
    /// so a window left set here leaks into every test that runs afterwards —
    /// which is exactly how this class broke
    /// <c>SystemAdminIntegrationTests.Retention_defaults_to_keeping_everything</c>
    /// the first time it ran. Anything that writes the singleton has to put it
    /// back.
    /// </summary>
    public async Task DisposeAsync()
    {
        if (!_fx.Available) return;

        using var scope = _fx.Scope();
        var db = _fx.Db(scope);

        var settings = await db.InstanceSettings
            .SingleOrDefaultAsync(s => s.Id == InstanceSettings.SingletonId);
        if (settings is null) return;

        settings.FindingRetentionDays = null;
        settings.BuildRetentionDays = null;
        await db.SaveChangesAsync();
    }

    [SkippableFact]
    public async Task With_no_window_configured_nothing_is_deleted()
    {
        Skip.IfNot(_fx.Available);

        // Keeping everything is the default and the honest one. Evidence you
        // deleted is evidence you cannot produce.
        var world = await SeedAsync(findingDays: null, buildDays: null);
        using var scope = _fx.Scope();
        var retention = scope.ServiceProvider.GetRequiredService<RetentionService>();
        var db = _fx.Db(scope);

        var outcome = await retention.SweepAsync(world.AsOf);

        Assert.False(outcome.Enabled);
        Assert.True(await db.Findings.AnyAsync(f => f.Id == world.OldFindingId));
    }

    [SkippableFact]
    public async Task An_old_finding_past_the_window_is_deleted()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync(findingDays: 90, buildDays: null);
        using var scope = _fx.Scope();
        var retention = scope.ServiceProvider.GetRequiredService<RetentionService>();
        var db = _fx.Db(scope);

        await retention.SweepAsync(world.AsOf);

        Assert.False(await db.Findings.AnyAsync(f => f.Id == world.OldFindingId));
    }

    [SkippableFact]
    public async Task Age_is_measured_on_last_seen_not_first_seen()
    {
        Skip.IfNot(_fx.Available);

        // A finding first raised two years ago and still present on last
        // night's build is a CURRENT problem. Deleting it for being old would
        // remove the most overdue items first, which is exactly backwards.
        var world = await SeedAsync(findingDays: 90, buildDays: null);
        using var scope = _fx.Scope();
        var retention = scope.ServiceProvider.GetRequiredService<RetentionService>();
        var db = _fx.Db(scope);

        await retention.SweepAsync(world.AsOf);

        Assert.True(await db.Findings.AnyAsync(f => f.Id == world.OldButStillSeenId));
    }

    [SkippableFact]
    public async Task A_finding_a_poam_item_links_is_kept()
    {
        Skip.IfNot(_fx.Available);

        // A POA&M is an open commitment to fix something. Deleting the thing it
        // points at leaves a plan of action whose subject cannot be inspected.
        var world = await SeedAsync(findingDays: 90, buildDays: null);
        using var scope = _fx.Scope();
        var retention = scope.ServiceProvider.GetRequiredService<RetentionService>();
        var db = _fx.Db(scope);

        var outcome = await retention.SweepAsync(world.AsOf);

        Assert.True(await db.Findings.AnyAsync(f => f.Id == world.PoamLinkedFindingId));
        Assert.True(outcome.FindingsKept > 0);
    }

    [SkippableFact]
    public async Task A_suppressed_finding_is_kept()
    {
        Skip.IfNot(_fx.Available);

        // The decision outliving its subject is how a suppression becomes
        // unexplainable — a reason on file pointing at nothing.
        var world = await SeedAsync(findingDays: 90, buildDays: null);
        using var scope = _fx.Scope();
        var retention = scope.ServiceProvider.GetRequiredService<RetentionService>();
        var db = _fx.Db(scope);

        await retention.SweepAsync(world.AsOf);

        Assert.True(await db.Findings.AnyAsync(f => f.Id == world.SuppressedFindingId));
    }

    [SkippableFact]
    public async Task An_accepted_finding_is_kept()
    {
        Skip.IfNot(_fx.Available);

        // A signed risk decision about that exact finding.
        var world = await SeedAsync(findingDays: 90, buildDays: null);
        using var scope = _fx.Scope();
        var retention = scope.ServiceProvider.GetRequiredService<RetentionService>();
        var db = _fx.Db(scope);

        await retention.SweepAsync(world.AsOf);

        Assert.True(await db.Findings.AnyAsync(f => f.Id == world.AcceptedFindingId));
    }

    [SkippableFact]
    public async Task An_old_build_past_the_window_is_deleted()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync(findingDays: null, buildDays: 30);
        using var scope = _fx.Scope();
        var retention = scope.ServiceProvider.GetRequiredService<RetentionService>();
        var db = _fx.Db(scope);

        await retention.SweepAsync(world.AsOf);

        Assert.False(await db.ComponentVersions.AnyAsync(v => v.Id == world.OldBuildId));
    }

    [SkippableFact]
    public async Task A_build_an_attestation_covers_is_kept()
    {
        Skip.IfNot(_fx.Available);

        // The snapshot stores its own document, so the signature stays
        // verifiable either way — but an assessor following an attestation back
        // to the build it names should find the build, not a gap.
        var world = await SeedAsync(findingDays: null, buildDays: 30);
        using var scope = _fx.Scope();
        var retention = scope.ServiceProvider.GetRequiredService<RetentionService>();
        var db = _fx.Db(scope);

        var outcome = await retention.SweepAsync(world.AsOf);

        Assert.True(await db.ComponentVersions.AnyAsync(v => v.Id == world.AttestedBuildId));
        Assert.True(outcome.BuildsKept > 0);
    }

    [SkippableFact]
    public async Task A_recent_build_is_kept()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync(findingDays: null, buildDays: 30);
        using var scope = _fx.Scope();
        var retention = scope.ServiceProvider.GetRequiredService<RetentionService>();
        var db = _fx.Db(scope);

        await retention.SweepAsync(world.AsOf);

        Assert.True(await db.ComponentVersions.AnyAsync(v => v.Id == world.RecentBuildId));
    }

    [SkippableFact]
    public async Task A_sweep_that_deletes_something_is_audited()
    {
        Skip.IfNot(_fx.Available);

        // "Where did the March findings go" has exactly one correct answer and
        // it should be findable.
        var world = await SeedAsync(findingDays: 90, buildDays: null);
        using var scope = _fx.Scope();
        var retention = scope.ServiceProvider.GetRequiredService<RetentionService>();
        var db = _fx.Db(scope);

        var before = await db.AuditEntries.CountAsync(a => a.Action == "retention.swept");
        await retention.SweepAsync(world.AsOf);
        var after = await db.AuditEntries.CountAsync(a => a.Action == "retention.swept");

        Assert.True(after > before);
    }

    // ---- Seed ----------------------------------------------------------------

    private sealed record World(
        Guid OldFindingId, Guid OldButStillSeenId, Guid PoamLinkedFindingId,
        Guid SuppressedFindingId, Guid AcceptedFindingId,
        Guid OldBuildId, Guid AttestedBuildId, Guid RecentBuildId,
        DateTimeOffset AsOf);

    private async Task<World> SeedAsync(int? findingDays, int? buildDays)
    {
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);

        var now = DateTimeOffset.UtcNow;
        var suffix = Guid.NewGuid().ToString("N")[..8];

        // The retention settings are a singleton, so every test in this class
        // rewrites them. They run sequentially within the collection.
        var settings = await db.InstanceSettings
            .SingleOrDefaultAsync(s => s.Id == InstanceSettings.SingletonId);

        if (settings is null)
        {
            settings = new InstanceSettings();
            db.InstanceSettings.Add(settings);
        }
        settings.FindingRetentionDays = findingDays;
        settings.BuildRetentionDays = buildDays;

        var user = new User
        {
            Login = $"ret-{suffix}",
            DisplayName = "Retention Tester",
            Email = $"ret-{suffix}@example.test",
            IsApproved = true,
        };
        db.Users.Add(user);

        var client = new Client { Name = $"ret-client-{suffix}" };
        var project = new Project { ClientId = client.Id, Name = $"ret-project-{suffix}" };
        var component = new Component { ProjectId = project.Id, Name = "api" };

        db.Clients.Add(client);
        db.Projects.Add(project);
        db.Components.Add(component);

        // Old enough for both windows, and the one an attestation covers.
        var attestedSha = $"{suffix}attested";
        var oldBuild = Build(db, component.Id, $"{suffix}old", now.AddDays(-400));
        var attestedBuild = Build(db, component.Id, attestedSha, now.AddDays(-400));
        var recentBuild = Build(db, component.Id, $"{suffix}new", now.AddDays(-1));

        db.AttestationSnapshots.Add(new AttestationSnapshot
        {
            ProjectId = project.Id,
            CommitSha = attestedSha,
            DocumentJson = "{}",
            RiskPolicyName = "Test policy",
            Score = 10,
            Band = "green",
            GeneratedByUserId = user.Id,
        });

        var stale = Finding(db, oldBuild.Id, $"OLD-{suffix}", now.AddDays(-400), FindingStatus.Open);
        var current = Finding(db, recentBuild.Id, $"CURRENT-{suffix}", now.AddDays(-1), FindingStatus.Open);
        // Deliberately: first seen long ago, still seen yesterday.
        current.FirstSeen = now.AddDays(-700);

        var linked = Finding(db, oldBuild.Id, $"POAM-{suffix}", now.AddDays(-400), FindingStatus.Open);
        var suppressed = Finding(db, oldBuild.Id, $"SUPP-{suffix}", now.AddDays(-400), FindingStatus.Suppressed);
        var accepted = Finding(db, oldBuild.Id, $"ACC-{suffix}", now.AddDays(-400), FindingStatus.Accepted);

        db.PoamItems.Add(new PoamItem
        {
            ProjectId = project.Id,
            Title = "Fix the thing",
            WeaknessDescription = "It is broken.",
            Severity = Severity.High,
            AuthorUserId = user.Id,
            LinkedFindingIds = [linked.Id],
        });

        db.Suppressions.Add(new Suppression
        {
            Scope = SuppressionScope.SingleFinding,
            FindingId = suppressed.Id,
            ClientId = client.Id,
            ProjectId = project.Id,
            ComponentId = component.Id,
            CreatedByUserId = user.Id,
            CreatedByRole = ProjectRole.LeadDev,
            Reason = "Known, deferred.",
            ExpiresAt = now.AddDays(30),
        });

        await db.SaveChangesAsync();

        return new World(
            stale.Id, current.Id, linked.Id, suppressed.Id, accepted.Id,
            oldBuild.Id, attestedBuild.Id, recentBuild.Id, now);
    }

    private static ComponentVersion Build(
        Tamp.Findings.Data.FindingsDbContext db, Guid componentId, string sha, DateTimeOffset created)
    {
        var version = new ComponentVersion
        {
            ComponentId = componentId,
            VersionString = "1.0.0",
            CommitSha = sha,
            CreatedAt = created,
        };
        db.ComponentVersions.Add(version);
        return version;
    }

    private static Finding Finding(
        Tamp.Findings.Data.FindingsDbContext db, Guid versionId, string ruleId,
        DateTimeOffset lastSeen, FindingStatus status)
    {
        var finding = new Finding
        {
            ComponentVersionId = versionId,
            Hash = ruleId,
            Scanner = ScannerKind.OpenGrep,
            RuleId = ruleId,
            Severity = Severity.Medium,
            Title = ruleId,
            FilePath = "src/Api/Program.cs",
            Line = 3,
            Status = status,
            FirstSeen = lastSeen,
            LastSeen = lastSeen,
        };
        db.Findings.Add(finding);
        return finding;
    }
}
