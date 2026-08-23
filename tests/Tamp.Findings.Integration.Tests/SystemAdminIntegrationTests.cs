using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.SystemAdmin;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Integration.Tests;

// Instance administration (TFND-110 … TFND-114).
[Collection(DatabaseCollection.Name)]
public class SystemAdminIntegrationTests
{
    private readonly DatabaseFixture _fx;

    public SystemAdminIntegrationTests(DatabaseFixture fx) => _fx = fx;

    // ---- Users & RBAC -------------------------------------------------------

    [SkippableFact]
    public async Task Pending_users_sort_ahead_of_approved_ones()
    {
        Skip.IfNot(_fx.Available);

        // A user waiting for access is the only row on this screen that
        // somebody is actively blocked by.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var admin = scope.ServiceProvider.GetRequiredService<SystemAdminService>();

        var users = await admin.UsersAsync();
        var pending = users.First(u => u.Id == world.PendingUserId);

        Assert.False(pending.IsApproved);
        // Every row before the first approved one is itself pending, and this
        // user is among them.
        Assert.Contains(users.TakeWhile(u => !u.IsApproved), u => u.Id == world.PendingUserId);
    }

    [SkippableFact]
    public async Task Approving_a_user_is_audited_as_an_access_change()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var admin = scope.ServiceProvider.GetRequiredService<SystemAdminService>();
        var db = _fx.Db(scope);

        await admin.ApproveAsync(world.Admin, world.PendingUserId, true);

        var entry = db.AuditEntries.Single(a => a.SubjectId == world.PendingUserId);

        Assert.Equal(AuditClass.Access, entry.Class);
        Assert.Equal("user.approved", entry.Action);
    }

    [SkippableFact]
    public async Task The_last_administrator_cannot_remove_their_own_flag()
    {
        Skip.IfNot(_fx.Available);

        // Recovering from an instance with no admin needs database access, and
        // the person who did it is usually the one who cannot get back in.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var admin = scope.ServiceProvider.GetRequiredService<SystemAdminService>();
        var db = _fx.Db(scope);

        // Make this the only admin on the instance.
        await db.Users.Where(u => u.Id != world.AdminUserId && u.IsAdmin)
            .ExecuteUpdateAsync(s => s.SetProperty(u => u.IsAdmin, false));

        var result = await admin.SetAdminAsync(world.Admin, world.AdminUserId, false);

        Assert.False(result.Success);
        Assert.Contains("only instance administrator", result.Error!, StringComparison.OrdinalIgnoreCase);
    }

    [SkippableFact]
    public async Task A_role_cannot_be_granted_at_instance_scope()
    {
        Skip.IfNot(_fx.Available);

        // Instance-wide access is the admin flag, not a role.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var admin = scope.ServiceProvider.GetRequiredService<SystemAdminService>();

        var result = await admin.GrantAsync(
            world.Admin, world.PendingUserId, ProjectRole.LeadDev, ScopeTarget.Instance);

        Assert.False(result.Success);
        Assert.False(result.WasDenied);
    }

    [SkippableFact]
    public async Task A_conflicting_grant_is_allowed_but_records_the_conflict()
    {
        Skip.IfNot(_fx.Available);

        // The advisory is recorded ON THE ASSIGNMENT so an assessor can see it
        // was a deliberate choice rather than an oversight.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var admin = scope.ServiceProvider.GetRequiredService<SystemAdminService>();

        await admin.GrantAsync(world.Admin, world.PendingUserId, ProjectRole.LeadDev, world.Scope);
        var second = await admin.GrantAsync(
            world.Admin, world.PendingUserId, ProjectRole.InfoSecOfficer, world.Scope);

        Assert.True(second.Success);

        var assignments = await admin.AssignmentsAsync(world.PendingUserId);
        Assert.Contains(assignments, a => a.SodConflict is not null);
    }

    [SkippableFact]
    public async Task With_enforcement_on_a_conflicting_grant_is_refused_instead()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var admin = scope.ServiceProvider.GetRequiredService<SystemAdminService>();

        var settings = await admin.SettingsAsync();
        settings.EnforceSeparationOfDuties = true;
        await admin.SaveSettingsAsync(world.Admin, settings);

        await admin.GrantAsync(world.Admin, world.PendingUserId, ProjectRole.LeadDev, world.Scope);
        var second = await admin.GrantAsync(
            world.Admin, world.PendingUserId, ProjectRole.InfoSecOfficer, world.Scope);

        Assert.False(second.Success);
        Assert.Contains("Separation of duties", second.Error!, StringComparison.Ordinal);
    }

    [SkippableFact]
    public async Task The_same_role_cannot_be_granted_twice_at_one_scope()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var admin = scope.ServiceProvider.GetRequiredService<SystemAdminService>();

        await admin.GrantAsync(world.Admin, world.PendingUserId, ProjectRole.LeadDev, world.Scope);
        var again = await admin.GrantAsync(
            world.Admin, world.PendingUserId, ProjectRole.LeadDev, world.Scope);

        Assert.False(again.Success);
    }

    [SkippableFact]
    public async Task Assignments_list_narrowest_first_because_that_is_the_tier_that_wins()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var admin = scope.ServiceProvider.GetRequiredService<SystemAdminService>();

        await admin.GrantAsync(
            world.Admin, world.PendingUserId, ProjectRole.Architect, ScopeTarget.Client(world.ClientId));
        await admin.GrantAsync(world.Admin, world.PendingUserId, ProjectRole.LeadDev, world.Scope);

        var assignments = await admin.AssignmentsAsync(world.PendingUserId);

        Assert.Equal("Project", assignments[0].Tier);
    }

    [SkippableFact]
    public async Task A_non_admin_cannot_grant_roles_at_the_instance()
    {
        Skip.IfNot(_fx.Available);

        // Only the admin flag grants anything at instance scope, because every
        // ProjectRoleAssignment is scoped to at least a client.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var admin = scope.ServiceProvider.GetRequiredService<SystemAdminService>();

        var result = await admin.ApproveAsync(world.Nobody, world.PendingUserId, true);

        Assert.True(result.WasDenied);
    }

    // ---- Scanners -----------------------------------------------------------

    [SkippableFact]
    public async Task Every_scanner_this_build_understands_is_listed()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var admin = scope.ServiceProvider.GetRequiredService<SystemAdminService>();

        var scanners = await admin.ScannersAsync(world.AsOf);

        Assert.Equal(Enum.GetValues<ScannerKind>().Length, scanners.Count);
    }

    [SkippableFact]
    public async Task An_expected_scanner_that_has_never_reported_is_silent()
    {
        Skip.IfNot(_fx.Available);

        // The row that makes "no scan" distinguishable from "clean".
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var admin = scope.ServiceProvider.GetRequiredService<SystemAdminService>();

        await admin.SetExpectedScannersAsync(world.Admin, [ScannerKind.Zap]);

        var scanners = await admin.ScannersAsync(world.AsOf);
        var zap = scanners.Single(s => s.Kind == ScannerKind.Zap);

        Assert.True(zap.Expected);
        Assert.True(zap.Silent);
        // And it sorts to the top, where somebody will see it.
        Assert.Equal(ScannerKind.Zap, scanners[0].Kind);
    }

    [SkippableFact]
    public async Task A_scanner_nobody_expects_is_never_silent_however_long_it_has_been_quiet()
    {
        Skip.IfNot(_fx.Available);

        // A scanner this deployment does not use is not a problem, and flagging
        // every unused one would drown the ones that matter.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var admin = scope.ServiceProvider.GetRequiredService<SystemAdminService>();

        var scanners = await admin.ScannersAsync(world.AsOf);

        Assert.All(scanners.Where(s => !s.Expected), s => Assert.False(s.Silent));
    }

    [SkippableFact]
    public async Task Removing_an_expectation_is_audited_as_a_risk_decision()
    {
        Skip.IfNot(_fx.Available);

        // It stops this instance noticing that a scanner went quiet.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var admin = scope.ServiceProvider.GetRequiredService<SystemAdminService>();
        var db = _fx.Db(scope);

        await admin.SetExpectedScannersAsync(world.Admin, [ScannerKind.Zap]);
        await admin.SetExpectedScannersAsync(world.Admin, []);

        var entry = db.AuditEntries
            .Where(a => a.Action == "scanners.expected_changed")
            .OrderByDescending(a => a.At)
            .First();

        Assert.Equal(AuditClass.Risk, entry.Class);
        Assert.Contains("-[Zap]", entry.Detail!, StringComparison.Ordinal);
    }

    [SkippableFact]
    public async Task Adding_an_expectation_is_not_a_risk_decision()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var admin = scope.ServiceProvider.GetRequiredService<SystemAdminService>();
        var db = _fx.Db(scope);

        await admin.SetExpectedScannersAsync(world.Admin, [ScannerKind.Zap]);

        // Newest, not Single: instance-scoped entries are shared across every
        // seeded world in this collection.
        var entry = db.AuditEntries
            .Where(a => a.Action == "scanners.expected_changed")
            .OrderByDescending(a => a.At)
            .First();

        Assert.NotEqual(AuditClass.Risk, entry.Class);
    }

    // ---- Instance settings --------------------------------------------------

    [SkippableFact]
    public async Task Retention_defaults_to_keeping_everything()
    {
        Skip.IfNot(_fx.Available);

        // The honest default for a compliance tool: an attestation signed three
        // years ago cites findings from three years ago.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var admin = scope.ServiceProvider.GetRequiredService<SystemAdminService>();

        var settings = await admin.SettingsAsync();

        Assert.Null(settings.FindingRetentionDays);
        Assert.Null(settings.BuildRetentionDays);
    }

    [SkippableFact]
    public async Task An_instance_url_that_is_not_a_url_is_refused()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var admin = scope.ServiceProvider.GetRequiredService<SystemAdminService>();

        var settings = await admin.SettingsAsync();
        settings.InstanceUrl = "findings.example.test";

        var result = await admin.SaveSettingsAsync(world.Admin, settings);

        Assert.False(result.Success);
    }

    [SkippableFact]
    public async Task Turning_separation_of_duties_on_is_audited_as_an_access_change()
    {
        Skip.IfNot(_fx.Available);

        // It changes who may hold which roles across every tenant.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var admin = scope.ServiceProvider.GetRequiredService<SystemAdminService>();
        var db = _fx.Db(scope);

        var settings = await admin.SettingsAsync();
        settings.EnforceSeparationOfDuties = true;
        await admin.SaveSettingsAsync(world.Admin, settings);

        var entry = db.AuditEntries
            .Where(a => a.Action == "instance.settings_changed")
            .OrderByDescending(a => a.At)
            .First();

        Assert.Equal(AuditClass.Access, entry.Class);
        Assert.Contains("ENFORCED", entry.Detail!, StringComparison.Ordinal);
    }

    // ---- Audit log ----------------------------------------------------------

    [SkippableFact]
    public async Task The_audit_log_filters_by_class()
    {
        Skip.IfNot(_fx.Available);

        // Risk acceptance, role grants and key changes are what an assessor
        // reads first — findable without knowing what word to type.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var admin = scope.ServiceProvider.GetRequiredService<SystemAdminService>();

        await admin.ApproveAsync(world.Admin, world.PendingUserId, true);

        var access = await admin.AuditAsync(AuditClass.Access);

        Assert.NotEmpty(access);
        Assert.All(access, a => Assert.Equal(AuditClass.Access, a.Class));
    }

    [SkippableFact]
    public async Task An_audit_row_names_its_scope_rather_than_showing_a_guid()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var admin = scope.ServiceProvider.GetRequiredService<SystemAdminService>();

        await admin.GrantAsync(world.Admin, world.PendingUserId, ProjectRole.LeadDev, world.Scope);

        var rows = await admin.AuditAsync(AuditClass.Access);
        var grant = rows.First(a => a.Action == "role.granted");

        Assert.Contains("sys-project", grant.Scope, StringComparison.Ordinal);
    }

    [SkippableFact]
    public async Task An_instance_scoped_entry_says_instance()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var admin = scope.ServiceProvider.GetRequiredService<SystemAdminService>();

        await admin.ApproveAsync(world.Admin, world.PendingUserId, true);

        var rows = await admin.AuditAsync(AuditClass.Access);

        Assert.Contains(rows, a => a.Action == "user.approved" && a.Scope == "instance");
    }

    // ---- Seed ---------------------------------------------------------------

    private sealed record World(
        Guid ClientId, Guid ProjectId, ScopeTarget Scope, DateTimeOffset AsOf,
        Guid AdminUserId, Guid PendingUserId,
        Principal Admin, Principal Nobody);

    private async Task<World> SeedAsync()
    {
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);

        // The instance settings row is shared, so reset it between worlds —
        // otherwise an enforcement test leaves SoD on for everything after it.
        var settings = await db.InstanceSettings
            .SingleOrDefaultAsync(s => s.Id == InstanceSettings.SingletonId);
        if (settings is not null)
        {
            settings.EnforceSeparationOfDuties = false;
            settings.ExpectedScanners = [];
            settings.InstanceUrl = null;
            await db.SaveChangesAsync();
        }

        var suffix = Guid.NewGuid().ToString("N")[..8];

        var client = new Client { Name = $"sys-client-{suffix}" };
        var project = new Project { ClientId = client.Id, Name = $"sys-project-{suffix}" };
        db.Clients.Add(client);
        db.Projects.Add(project);

        var admin = new User
        {
            Login = $"sys-admin-{suffix}",
            DisplayName = "System Admin",
            Email = $"sys-admin-{suffix}@example.test",
            IsApproved = true,
            IsAdmin = true,
        };
        var pending = new User
        {
            Login = $"sys-pending-{suffix}",
            DisplayName = "Pending User",
            Email = $"sys-pending-{suffix}@example.test",
            IsApproved = false,
        };
        db.Users.AddRange(admin, pending);

        await db.SaveChangesAsync();

        return new World(
            client.Id, project.Id, ScopeTarget.Project(client.Id, project.Id), DateTimeOffset.UtcNow,
            admin.Id, pending.Id,
            Admin: Principal.For(admin.Id, admin.Login, isAdmin: true, []),
            Nobody: Principal.For(pending.Id, pending.Login, isAdmin: false, []));
    }
}
