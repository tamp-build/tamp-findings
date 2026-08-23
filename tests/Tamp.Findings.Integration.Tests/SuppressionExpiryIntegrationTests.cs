using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Suppressions;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Integration.Tests;

// Expired suppressions reopen their findings (TFND-11 / F10.5).
//
// The ingest path already reopens on the next scan, so what these cover is the
// gap that leaves: every query in this product filters on Open, so between a
// suppression expiring and the next build of that exact component, the finding
// is invisible — in the counts, in the score and in every gate. On a component
// that ships quarterly that is months of a finding being hidden AFTER the
// decision to hide it ran out.
[Collection(DatabaseCollection.Name)]
public class SuppressionExpiryIntegrationTests
{
    private readonly DatabaseFixture _fx;

    public SuppressionExpiryIntegrationTests(DatabaseFixture fx) => _fx = fx;

    [SkippableFact]
    public async Task An_expired_suppression_reopens_its_finding_without_a_new_build()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var sweep = scope.ServiceProvider.GetRequiredService<SuppressionExpiryService>();
        var db = _fx.Db(scope);

        await sweep.SweepAsync(world.AsOf);

        var finding = await db.Findings.AsNoTracking().SingleAsync(f => f.Id == world.LapsedFindingId);
        Assert.Equal(FindingStatus.Open, finding.Status);
    }

    [SkippableFact]
    public async Task A_finding_under_a_live_suppression_is_left_alone()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var sweep = scope.ServiceProvider.GetRequiredService<SuppressionExpiryService>();
        var db = _fx.Db(scope);

        await sweep.SweepAsync(world.AsOf);

        var finding = await db.Findings.AsNoTracking().SingleAsync(f => f.Id == world.LiveFindingId);
        Assert.Equal(FindingStatus.Suppressed, finding.Status);
    }

    [SkippableFact]
    public async Task One_of_two_suppressions_lapsing_does_not_reopen_anything()
    {
        Skip.IfNot(_fx.Available);

        // A finding can be covered twice. Reopening on "did any suppression
        // expire" rather than "is it still covered" would reopen findings
        // somebody deliberately re-suppressed — and they would have to
        // re-suppress them again every time.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var sweep = scope.ServiceProvider.GetRequiredService<SuppressionExpiryService>();
        var db = _fx.Db(scope);

        await sweep.SweepAsync(world.AsOf);

        var finding = await db.Findings.AsNoTracking().SingleAsync(f => f.Id == world.DoublyCoveredId);
        Assert.Equal(FindingStatus.Suppressed, finding.Status);
    }

    [SkippableFact]
    public async Task An_accepted_finding_is_never_reopened()
    {
        Skip.IfNot(_fx.Available);

        // Accepted is an explicit "we know, and we are accepting the risk"
        // decision with its own lifecycle. A sweep that reopened those would be
        // overruling somebody who signed something.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var sweep = scope.ServiceProvider.GetRequiredService<SuppressionExpiryService>();
        var db = _fx.Db(scope);

        await sweep.SweepAsync(world.AsOf);

        var finding = await db.Findings.AsNoTracking().SingleAsync(f => f.Id == world.AcceptedFindingId);
        Assert.Equal(FindingStatus.Accepted, finding.Status);
    }

    [SkippableFact]
    public async Task The_reopen_is_audited_as_a_risk_event()
    {
        Skip.IfNot(_fx.Available);

        // It changes the score, and it can flip a gate from pass to fail with
        // nobody touching the project. That is exactly what an assessor would
        // want to find in the log.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var sweep = scope.ServiceProvider.GetRequiredService<SuppressionExpiryService>();
        var db = _fx.Db(scope);

        await sweep.SweepAsync(world.AsOf);

        var entry = await db.AuditEntries.AsNoTracking()
            .SingleAsync(a => a.SubjectId == world.LapsedFindingId);

        Assert.Equal(AuditClass.Risk, entry.Class);
        Assert.Equal("finding.suppression_expired", entry.Action);
    }

    [SkippableFact]
    public async Task The_audit_entry_names_the_suppression_that_lapsed()
    {
        Skip.IfNot(_fx.Available);

        // "A suppression expired" without saying which one leaves the reader to
        // go looking, and the point of the entry is that they should not have to.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var sweep = scope.ServiceProvider.GetRequiredService<SuppressionExpiryService>();
        var db = _fx.Db(scope);

        await sweep.SweepAsync(world.AsOf);

        var entry = await db.AuditEntries.AsNoTracking()
            .SingleAsync(a => a.SubjectId == world.LapsedFindingId);

        Assert.Contains("shipped it anyway", entry.Detail!, StringComparison.Ordinal);
    }

    [SkippableFact]
    public async Task The_sweep_is_idempotent()
    {
        Skip.IfNot(_fx.Available);

        // It runs hourly. A second pass finding nothing to do is what stops the
        // audit log filling with one entry per hour for the same finding.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var sweep = scope.ServiceProvider.GetRequiredService<SuppressionExpiryService>();

        var first = await sweep.SweepAsync(world.AsOf);
        var second = await sweep.SweepAsync(world.AsOf);

        Assert.True(first > 0);
        Assert.Equal(0, second);
    }

    [SkippableFact]
    public async Task A_suppression_expiring_in_another_tenant_does_not_reopen_this_one()
    {
        Skip.IfNot(_fx.Available);

        // The sweep matches through SuppressionMatcher, which is tenant-bounded
        // as of TFND-132. Worth pinning here too: a background job that
        // reopened another client's findings would be the same defect arriving
        // by a different route.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var sweep = scope.ServiceProvider.GetRequiredService<SuppressionExpiryService>();
        var db = _fx.Db(scope);

        await sweep.SweepAsync(world.AsOf);

        var foreign = await db.Findings.AsNoTracking().SingleAsync(f => f.Id == world.ForeignFindingId);
        Assert.Equal(FindingStatus.Suppressed, foreign.Status);
    }

    // ---- Seed ----------------------------------------------------------------

    private sealed record World(
        Guid LapsedFindingId, Guid LiveFindingId, Guid DoublyCoveredId,
        Guid AcceptedFindingId, Guid ForeignFindingId, DateTimeOffset AsOf);

    private async Task<World> SeedAsync()
    {
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);

        var suffix = Guid.NewGuid().ToString("N")[..8];
        var now = DateTimeOffset.UtcNow;

        var user = new User
        {
            Login = $"exp-{suffix}",
            DisplayName = "Expiry Author",
            Email = $"exp-{suffix}@example.test",
            IsApproved = true,
        };
        db.Users.Add(user);

        var (client, project, component, version) = Tree(db, $"exp-{suffix}");
        var (_, foreignProject, foreignComponent, foreignVersion) = Tree(db, $"exp-other-{suffix}");

        // Rule ids are suffixed per run, so a suppression seeded by one test
        // run cannot silence a finding seeded by another against the shared
        // database.
        var lapsedRule = $"LAPSED-{suffix}";
        var liveRule = $"LIVE-{suffix}";
        var doubleRule = $"DOUBLE-{suffix}";
        var acceptedRule = $"ACCEPTED-{suffix}";

        var lapsed = Finding(db, version.Id, lapsedRule, suffix, FindingStatus.Suppressed);
        var live = Finding(db, version.Id, liveRule, suffix, FindingStatus.Suppressed);
        var doubly = Finding(db, version.Id, doubleRule, suffix, FindingStatus.Suppressed);
        var accepted = Finding(db, version.Id, acceptedRule, suffix, FindingStatus.Accepted);
        var foreign = Finding(db, foreignVersion.Id, lapsedRule, suffix + "f", FindingStatus.Suppressed);

        db.Suppressions.AddRange(
            // Expired yesterday.
            Suppression(user.Id, client.Id, project.Id, component.Id, lapsedRule,
                "Deadline was immovable and we shipped it anyway.", now.AddDays(-1)),

            // Still live.
            Suppression(user.Id, client.Id, project.Id, component.Id, liveRule,
                "Under review with the vendor.", now.AddDays(30)),

            // Two, one lapsed and one live.
            Suppression(user.Id, client.Id, project.Id, component.Id, doubleRule,
                "First pass, expired.", now.AddDays(-1)),
            Suppression(user.Id, client.Id, project.Id, component.Id, doubleRule,
                "Re-suppressed after review.", now.AddDays(30)),

            // Accepted findings are untouchable, but seed a lapsed suppression
            // over it anyway so the test is exercising the guard rather than an
            // absence of coverage.
            Suppression(user.Id, client.Id, project.Id, component.Id, acceptedRule,
                "Superseded by the risk acceptance.", now.AddDays(-1)),

            // The other tenant's own, still live — so the foreign finding stays
            // suppressed for its own reasons and the assertion is about
            // tenancy, not about coverage.
            Suppression(user.Id, foreignProject.ClientId, foreignProject.Id, foreignComponent.Id,
                lapsedRule, "Another client's decision.", now.AddDays(30)));

        await db.SaveChangesAsync();

        return new World(lapsed.Id, live.Id, doubly.Id, accepted.Id, foreign.Id, now);
    }

    private static (Client, Project, Component, ComponentVersion) Tree(
        Tamp.Findings.Data.FindingsDbContext db, string name)
    {
        var client = new Client { Name = $"{name}-client" };
        var project = new Project { ClientId = client.Id, Name = $"{name}-project" };
        var component = new Component { ProjectId = project.Id, Name = "api" };
        var version = new ComponentVersion
        {
            ComponentId = component.Id, VersionString = "1.0.0", CommitSha = name + "eeeeee",
        };

        db.Clients.Add(client);
        db.Projects.Add(project);
        db.Components.Add(component);
        db.ComponentVersions.Add(version);

        return (client, project, component, version);
    }

    private static Finding Finding(
        Tamp.Findings.Data.FindingsDbContext db, Guid versionId, string ruleId, string suffix,
        FindingStatus status)
    {
        var finding = new Finding
        {
            ComponentVersionId = versionId,
            Hash = $"{ruleId}-{suffix}",
            Scanner = ScannerKind.OpenGrep,
            RuleId = ruleId,
            Severity = Severity.High,
            Title = ruleId,
            FilePath = "src/Api/Program.cs",
            Line = 7,
            Status = status,
        };
        db.Findings.Add(finding);
        return finding;
    }

    private static Suppression Suppression(
        Guid userId, Guid clientId, Guid projectId, Guid componentId, string ruleId,
        string reason, DateTimeOffset expiresAt) => new()
    {
        Scope = SuppressionScope.RuleOnComponent,
        RuleId = ruleId,
        ComponentId = componentId,
        ClientId = clientId,
        ProjectId = projectId,
        CreatedByUserId = userId,
        CreatedByRole = ProjectRole.LeadDev,
        Reason = reason,
        ExpiresAt = expiresAt,
    };
}
