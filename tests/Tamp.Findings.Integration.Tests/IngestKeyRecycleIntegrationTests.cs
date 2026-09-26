using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Approvals;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Ingest;
using Tamp.Findings.Application.Projects;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Integration.Tests;

// Ingest-key recycling with a grace period and a second approver (TFND-124).
//
// The hazard the grace period removes: a recycled key used to die at once, the
// pipeline stopped producing receipts, and every build read UNKNOWN until
// someone noticed. Now the old key eases out over a window, and — when SoD is
// enforced — a second key manager has to approve the recycle.
[Collection(DatabaseCollection.Name)]
public class IngestKeyRecycleIntegrationTests
{
    private readonly DatabaseFixture _fx;

    public IngestKeyRecycleIntegrationTests(DatabaseFixture fx) => _fx = fx;

    [SkippableFact]
    public async Task Recycling_graces_the_old_key_rather_than_killing_it()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var keys = scope.ServiceProvider.GetRequiredService<ProjectKeyService>();
        var db = _fx.Db(scope);

        await keys.RecycleAsync(world.Lead, world.Scope, world.ProjectId);   // first key
        var second = await keys.RecycleAsync(world.Lead, world.Scope, world.ProjectId); // recycle
        Assert.True(second.Success);

        var tokens = db.IngestTokens
            .Where(t => t.ProjectId == world.ProjectId)
            .OrderBy(t => t.CreatedAt)
            .ToArray();

        Assert.Equal(2, tokens.Length);
        // The old key is NOT hard-revoked; it is graced.
        Assert.Null(tokens[0].RevokedAt);
        Assert.NotNull(tokens[0].GraceExpiresAt);
        // The new key carries no grace — it is the live one.
        Assert.Null(tokens[1].GraceExpiresAt);
    }

    [SkippableFact]
    public async Task A_graced_key_works_until_its_window_closes_then_stops()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var keys = scope.ServiceProvider.GetRequiredService<ProjectKeyService>();
        var tokens = scope.ServiceProvider.GetRequiredService<IngestTokenService>();
        var db = _fx.Db(scope);

        var first = await keys.RecycleAsync(world.Lead, world.Scope, world.ProjectId);
        var oldPlaintext = first.Value!;
        await keys.RecycleAsync(world.Lead, world.Scope, world.ProjectId); // graces the old key

        // Within the window, the old key still authenticates.
        Assert.NotNull(await tokens.ValidateAsync(oldPlaintext, default));

        // Force the window shut.
        var old = db.IngestTokens.OrderBy(t => t.CreatedAt).First(t => t.ProjectId == world.ProjectId);
        old.GraceExpiresAt = DateTimeOffset.UtcNow.AddSeconds(-1);
        await db.SaveChangesAsync();

        // Now it is rejected as surely as a revoked key — without RevokedAt ever
        // being set.
        Assert.Null(await tokens.ValidateAsync(oldPlaintext, default));
        Assert.Null(db.IngestTokens.Single(t => t.Id == old.Id).RevokedAt);
    }

    [SkippableFact]
    public async Task With_separation_of_duties_enforced_direct_recycle_is_refused()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var keys = scope.ServiceProvider.GetRequiredService<ProjectKeyService>();
        var db = _fx.Db(scope);

        var settings = await db.InstanceSettings
            .SingleOrDefaultAsync(s => s.Id == InstanceSettings.SingletonId);
        if (settings is null) { settings = new InstanceSettings(); db.InstanceSettings.Add(settings); }
        settings!.EnforceSeparationOfDuties = true;
        await db.SaveChangesAsync();

        try
        {
            var result = await keys.RecycleAsync(world.Lead, world.Scope, world.ProjectId);
            Assert.False(result.Success);
            Assert.False(result.WasDenied);
            Assert.Contains("second approver", result.Error!, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            settings.EnforceSeparationOfDuties = false;
            await db.SaveChangesAsync();
        }
    }

    [SkippableFact]
    public async Task An_approved_recycle_mints_the_new_key_for_the_approver()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var keys = scope.ServiceProvider.GetRequiredService<ProjectKeyService>();
        var approvals = scope.ServiceProvider.GetRequiredService<ApprovalService>();
        var db = _fx.Db(scope);

        var request = await approvals.RequestAsync(
            world.Lead, world.Scope, ApprovalKind.IngestKeyRecycle,
            "IngestToken", world.ProjectId, justification: "Suspected leak.");
        Assert.True(request.Success);

        // The requester cannot approve their own recycle.
        var self = await keys.ApproveRecycleAsync(world.Lead, request.Value);
        Assert.True(self.WasDenied);

        // A different key manager approves and receives the new key.
        var approved = await keys.ApproveRecycleAsync(world.InfoSec, request.Value);
        Assert.True(approved.Success);
        Assert.StartsWith("prj_", approved.Value);

        Assert.Single(db.IngestTokens.Where(t => t.ProjectId == world.ProjectId).ToArray());
        Assert.Null(await approvals.ForSubjectAsync("IngestToken", world.ProjectId));
    }

    // ---- Seed ---------------------------------------------------------------

    private sealed record World(Guid ProjectId, ScopeTarget Scope, Principal Lead, Principal InfoSec);

    private async Task<World> SeedAsync()
    {
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);

        var suffix = Guid.NewGuid().ToString("N")[..8];
        var client = new Client { Name = $"key-client-{suffix}" };
        var project = new Project { ClientId = client.Id, Name = $"key-project-{suffix}" };
        db.Clients.Add(client);
        db.Projects.Add(project);

        var lead = new User
        {
            Login = $"key-lead-{suffix}", DisplayName = "Lead",
            Email = $"key-lead-{suffix}@example.test", IsApproved = true,
        };
        var infosec = new User
        {
            Login = $"key-infosec-{suffix}", DisplayName = "InfoSec",
            Email = $"key-infosec-{suffix}@example.test", IsApproved = true,
        };
        db.Users.AddRange(lead, infosec);
        await db.SaveChangesAsync();

        return new World(
            project.Id,
            ScopeTarget.Project(client.Id, project.Id),
            // Both hold ManageIngestKey; distinct users, so one can approve the other.
            Lead: Principal.For(lead.Id, lead.Login, isAdmin: false, [ProjectRole.LeadDev]),
            InfoSec: Principal.For(infosec.Id, infosec.Login, isAdmin: false, [ProjectRole.InfoSecOfficer]));
    }
}
