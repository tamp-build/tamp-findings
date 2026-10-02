using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.SystemAdmin;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Integration.Tests;

// SystemAdminService (users, roles, scanners, instance settings, audit) and PaidComponentRegistry.
[Collection(DatabaseCollection.Name)]
public class AppCovSystemAdminTests
{
    private readonly DatabaseFixture _fx;
    public AppCovSystemAdminTests(DatabaseFixture fx) => _fx = fx;

    // Runs the body and then puts the singleton settings row back exactly as it was.
    private async Task PreservingSettingsAsync(Func<Task> body)
    {
        InstanceSettings? original;
        using (var scope = _fx.Scope())
            original = await _fx.Db(scope).InstanceSettings.AsNoTracking().SingleOrDefaultAsync(s => s.Id == InstanceSettings.SingletonId);
        try { await body(); }
        finally
        {
            using var scope = _fx.Scope();
            var db = _fx.Db(scope);
            var row = await db.InstanceSettings.SingleOrDefaultAsync(s => s.Id == InstanceSettings.SingletonId);
            if (original is null) { if (row is not null) db.InstanceSettings.Remove(row); }
            else if (row is null) db.InstanceSettings.Add(original);
            else db.Entry(row).CurrentValues.SetValues(original);
            await db.SaveChangesAsync();
        }
    }

    [SkippableFact]
    public async Task Users_approval_admin_flag_and_role_grants()
    {
        Skip.IfNot(_fx.Available);
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var actors = await AppCovSeed.UsersAsync(db);
        var (client, project) = await AppCovSeed.ClientProjectAsync(db, "sa");
        var svc = scope.ServiceProvider.GetRequiredService<SystemAdminService>();
        var pending = new User { Login = $"cov-pending-{Guid.NewGuid():N}", DisplayName = "p", Email = "p@example.test", IsApproved = false };
        db.Users.Add(pending);
        await db.SaveChangesAsync();

        var users = await svc.UsersAsync();
        Assert.Contains(users, u => u.Id == pending.Id && !u.IsApproved);
        Assert.False(users.First().IsApproved && users.Any(u => !u.IsApproved));

        Assert.True((await svc.ApproveAsync(actors.Viewer, pending.Id, true)).WasDenied);
        Assert.False((await svc.ApproveAsync(actors.Admin, Guid.NewGuid(), true)).Success);
        Assert.False((await svc.ApproveAsync(actors.Admin, pending.Id, false)).Value);
        Assert.True((await svc.ApproveAsync(actors.Admin, pending.Id, true)).Value);
        Assert.True((await svc.ApproveAsync(actors.Admin, pending.Id, false)).Value);

        Assert.True((await svc.SetAdminAsync(actors.Viewer, pending.Id, true)).WasDenied);
        Assert.False((await svc.SetAdminAsync(actors.Admin, Guid.NewGuid(), true)).Success);
        Assert.False((await svc.SetAdminAsync(actors.Admin, pending.Id, false)).Value);
        Assert.True((await svc.SetAdminAsync(actors.Admin, pending.Id, true)).Value);
        Assert.True((await svc.SetAdminAsync(actors.Admin, pending.Id, false)).Value);

        var clientScope = ScopeTarget.Client(client.Id);
        var projectScope = ScopeTarget.Project(client.Id, project.Id);
        var target = actors.Lead.UserId;
        Assert.True((await svc.GrantAsync(actors.Viewer, target, ProjectRole.Architect, clientScope)).WasDenied);
        Assert.False((await svc.GrantAsync(actors.Admin, target, ProjectRole.Architect, ScopeTarget.Instance)).Success);
        Assert.False((await svc.GrantAsync(actors.Admin, Guid.NewGuid(), ProjectRole.Architect, clientScope)).Success);
        var first = await svc.GrantAsync(actors.Admin, target, ProjectRole.LeadDev, clientScope);
        Assert.True(first.Success);
        Assert.False((await svc.GrantAsync(actors.Admin, target, ProjectRole.LeadDev, clientScope)).Success);
        var conflicting = await svc.GrantAsync(actors.Admin, target, ProjectRole.InfoSecOfficer, clientScope);
        Assert.True(conflicting.Success);
        var onProject = await svc.GrantAsync(actors.Admin, target, ProjectRole.Architect, projectScope);
        Assert.True(onProject.Success);

        var assignments = await svc.AssignmentsAsync(target);
        Assert.Equal(3, assignments.Count);
        Assert.Equal("Project", assignments[0].Tier);
        Assert.Contains(assignments, a => a.SodConflict is not null);
        Assert.Contains((await svc.UsersAsync()), u => u.Id == target && u.HasSodConflict && u.AssignmentCount == 3);

        await PreservingSettingsAsync(async () =>
        {
            using var s = _fx.Scope();
            var d = _fx.Db(s);
            var row = await d.InstanceSettings.SingleOrDefaultAsync(x => x.Id == InstanceSettings.SingletonId);
            if (row is null) { d.InstanceSettings.Add(new InstanceSettings { EnforceSeparationOfDuties = true }); }
            else row.EnforceSeparationOfDuties = true;
            await d.SaveChangesAsync();
            var strict = s.ServiceProvider.GetRequiredService<SystemAdminService>();
            var refused = await strict.GrantAsync(actors.Admin, actors.Viewer.UserId, ProjectRole.LeadDev, clientScope);
            Assert.True(refused.Success);
            var refused2 = await strict.GrantAsync(actors.Admin, actors.Viewer.UserId, ProjectRole.InfoSecOfficer, clientScope);
            Assert.False(refused2.Success);
            Assert.Contains("Separation of duties", refused2.Error);
        });

        Assert.True((await svc.RevokeAsync(actors.Viewer, first.Value)).WasDenied);
        Assert.False((await svc.RevokeAsync(actors.Admin, Guid.NewGuid())).Value);
        Assert.True((await svc.RevokeAsync(actors.Admin, first.Value)).Value);
        Assert.Equal(2, (await svc.AssignmentsAsync(target)).Count);
    }

    [SkippableFact]
    public async Task Scanner_registry_and_expected_scanners()
    {
        Skip.IfNot(_fx.Available);
        await PreservingSettingsAsync(async () =>
        {
            using var scope = _fx.Scope();
            var db = _fx.Db(scope);
            var actors = await AppCovSeed.UsersAsync(db);
            var (_, project) = await AppCovSeed.ClientProjectAsync(db, "sa-scan");
            var cv = await AppCovSeed.BuildAsync(db, project.Id);
            db.ScanRunReceipts.Add(new ScanRunReceipt { ComponentVersionId = cv.Id, Scanner = ScannerKind.Syft, Status = ScanRunStatus.Succeeded, StartedAt = DateTimeOffset.UtcNow, CompletedAt = DateTimeOffset.UtcNow.AddDays(-90) });
            await db.SaveChangesAsync();
            var svc = scope.ServiceProvider.GetRequiredService<SystemAdminService>();

            Assert.True((await svc.SetExpectedScannersAsync(actors.Viewer, [ScannerKind.Syft])).WasDenied);
            await svc.SetExpectedScannersAsync(actors.Admin, []);
            Assert.Equal(0, (await svc.SetExpectedScannersAsync(actors.Admin, [])).Value);
            var changed = await svc.SetExpectedScannersAsync(actors.Admin, [ScannerKind.Syft, ScannerKind.Zap]);
            Assert.Equal(2, changed.Value);
            // The database is shared with every other test, so "silent" (expected but never reported) cannot
            // be assumed of any fixed scanner: include one that has genuinely never reported right now.
            var fixedKinds = new[] { ScannerKind.Syft, ScannerKind.OpenGrep, ScannerKind.Zap, ScannerKind.Nuclei };
            var reported = db.ScanRunReceipts.Select(r => r.Scanner).Distinct().ToHashSet();
            var quiet = Enum.GetValues<ScannerKind>().Last(k => !reported.Contains(k) && !fixedKinds.Contains(k));
            Assert.Equal(4, (await svc.SetExpectedScannersAsync(actors.Admin, [ScannerKind.OpenGrep, ScannerKind.Zap, ScannerKind.Nuclei, quiet])).Value);

            var rows = await svc.ScannersAsync(DateTimeOffset.UtcNow);
            Assert.Equal(Enum.GetValues<ScannerKind>().Length, rows.Count);
            Assert.True(rows[0].Silent);
            Assert.Contains(rows, r => r.Kind == ScannerKind.Zap && r.Expected);
            Assert.Contains(rows, r => r.Kind == ScannerKind.Syft && r.Runs > 0);

            foreach (var k in Enum.GetValues<ScannerKind>()) Assert.False(string.IsNullOrEmpty(SystemAdminService.ClassOf(k)));
            Assert.Equal("SAST", SystemAdminService.ClassOf(ScannerKind.Roslyn));
            Assert.Equal("DAST", SystemAdminService.ClassOf(ScannerKind.Zap));
            Assert.Equal("Supply chain", SystemAdminService.ClassOf(ScannerKind.Cosign));
            Assert.Equal("Secrets", SystemAdminService.ClassOf(ScannerKind.TruffleHog));
            Assert.Equal("Container / IaC", SystemAdminService.ClassOf(ScannerKind.Trivy));
            Assert.Equal("Other", SystemAdminService.ClassOf(ScannerKind.Stryker));
        });
    }

    [SkippableFact]
    public async Task Instance_settings_validation_save_and_audit()
    {
        Skip.IfNot(_fx.Available);
        await PreservingSettingsAsync(async () =>
        {
            using var scope = _fx.Scope();
            var db = _fx.Db(scope);
            var actors = await AppCovSeed.UsersAsync(db);
            var svc = scope.ServiceProvider.GetRequiredService<SystemAdminService>();
            var current = await svc.SettingsAsync();

            InstanceSettings P(Action<InstanceSettings> m) { var s = new InstanceSettings(); m(s); return s; }
            Assert.True((await svc.SaveSettingsAsync(actors.Viewer, P(_ => { }))).WasDenied);
            Assert.False((await svc.SaveSettingsAsync(actors.Admin, P(s => s.InstanceUrl = "not a url"))).Success);
            Assert.False((await svc.SaveSettingsAsync(actors.Admin, P(s => s.SessionLifetimeHours = 0))).Success);
            Assert.False((await svc.SaveSettingsAsync(actors.Admin, P(s => s.GitHubChecksEnabled = true))).Success);
            Assert.False((await svc.SaveSettingsAsync(actors.Admin, P(s => s.FindingRetentionDays = 0))).Success);
            Assert.False((await svc.SaveSettingsAsync(actors.Admin, P(s => s.BuildRetentionDays = 0))).Success);

            Assert.True((await svc.SaveSettingsAsync(actors.Admin, P(s =>
            {
                s.InstanceUrl = " https://findings.example "; s.EnforceSeparationOfDuties = true; s.McpEnabled = true; s.StrictVisibility = true;
                s.GitHubAppId = "99"; s.GitHubAppPrivateKeyProtected = "secret"; s.GitHubChecksEnabled = true; s.GitHubCheckName = " ";
                s.FindingRetentionDays = 30; s.BuildRetentionDays = 60; s.SmtpHost = "smtp"; s.SmtpPort = 25; s.SmtpFrom = "a@b.c";
                s.EnforcementMode = EnforcementMode.Enforcing; s.EnforcementLocked = true;
            }))).Success);
            var saved = await svc.SettingsAsync();
            Assert.Equal("https://findings.example", saved.InstanceUrl);
            Assert.Equal("tamp.findings", saved.GitHubCheckName);
            Assert.Equal("secret", saved.GitHubAppPrivateKeyProtected);
            Assert.True(saved.McpEnabled);

            // blank key keeps the stored one; toggling off MCP/SoD/strict/enforcement names each change
            Assert.True((await svc.SaveSettingsAsync(actors.Admin, P(s => { s.GitHubAppId = "99"; s.GitHubChecksEnabled = true; s.GitHubAppPrivateKeyProtected = "k"; s.GitHubCheckName = "x"; }))).Success);
            Assert.True((await svc.SaveSettingsAsync(actors.Admin, P(s => { }))).Success);
            Assert.True((await svc.SaveSettingsAsync(actors.Admin, P(s => { }))).Success);
            _ = current;

            var all = await svc.AuditAsync();
            Assert.Contains(all, a => a.Action == "instance.settings_changed" && a.Scope == "instance");
            Assert.Contains(all, a => a.Detail is not null && a.Detail.Contains("MCP endpoint", StringComparison.Ordinal));
            Assert.Contains(all, a => a.Detail is not null && a.Detail.Contains("gate enforcement", StringComparison.Ordinal));
            var risk = await svc.AuditAsync(AuditClass.Risk, take: 5000);
            Assert.All(risk, a => Assert.Equal(AuditClass.Risk, a.Class));
            Assert.True((await svc.AuditAsync(null, take: 0)).Count <= 1);
        });
    }

    [SkippableFact]
    public async Task Audit_rows_resolve_scope_names()
    {
        Skip.IfNot(_fx.Available);
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var actors = await AppCovSeed.UsersAsync(db);
        var (client, project) = await AppCovSeed.ClientProjectAsync(db, "sa-audit");
        var svc = scope.ServiceProvider.GetRequiredService<SystemAdminService>();
        await svc.GrantAsync(actors.Admin, actors.Lead.UserId, ProjectRole.LeadDev, ScopeTarget.Project(client.Id, project.Id));
        await svc.GrantAsync(actors.Admin, actors.Lead.UserId, ProjectRole.Architect, ScopeTarget.Client(client.Id));
        db.AuditEntries.Add(new AuditEntry { ActorLogin = "x", Action = "cov.ghost", Class = AuditClass.Other, ClientId = Guid.NewGuid() });
        db.AuditEntries.Add(new AuditEntry { ActorLogin = "x", Action = "cov.ghostp", Class = AuditClass.Other, ProjectId = Guid.NewGuid() });
        await db.SaveChangesAsync();

        var rows = await svc.AuditAsync(AuditClass.Access, 1000);
        Assert.Contains(rows, r => r.Scope == project.Name);
        Assert.Contains(rows, r => r.Scope == client.Name);
        var other = await svc.AuditAsync(AuditClass.Other, 1000);
        Assert.Contains(other, r => r.Scope == "(removed client)");
        Assert.Contains(other, r => r.Scope == "(removed project)");
    }

    [SkippableFact]
    public async Task Paid_component_registry_crud_and_seeding()
    {
        Skip.IfNot(_fx.Available);
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var actors = await AppCovSeed.UsersAsync(db);
        var svc = scope.ServiceProvider.GetRequiredService<PaidComponentRegistry>();
        var asOf = DateTimeOffset.UtcNow;

        await PaidComponentRegistry.SeedAsync(db);
        await PaidComponentRegistry.SeedAsync(db);
        var seeded = await svc.ListAsync(asOf);
        Assert.NotEmpty(seeded);
        var builtIn = seeded.First(r => r.IsBuiltIn);
        Assert.False((await svc.RemoveAsync(actors.Admin, builtIn.Id)).Success);

        var tag = Guid.NewGuid().ToString("N")[..8];
        Assert.True((await svc.AddAsync(actors.Viewer, "V", "P", "ab", null)).WasDenied);
        Assert.False((await svc.AddAsync(actors.Admin, " ", "P", "ab", null)).Success);
        Assert.False((await svc.AddAsync(actors.Admin, "V", " ", "ab", null)).Success);
        Assert.False((await svc.AddAsync(actors.Admin, "V", "P", "a", null)).Success);
        var added = await svc.AddAsync(actors.Admin, $"Vendor{tag}", "Prod", $"Cov.{tag}", " NuGet ");
        Assert.True(added.Success);
        Assert.False((await svc.AddAsync(actors.Admin, "V2", "P2", $"cov.{tag.ToUpperInvariant()}", "nuget")).Success);

        Assert.True((await svc.UpdateCostAsync(actors.Viewer, added.Value, 10, "USD", null, true, asOf)).WasDenied);
        Assert.False((await svc.UpdateCostAsync(actors.Admin, added.Value, -1, "USD", null, true, asOf)).Success);
        Assert.False((await svc.UpdateCostAsync(actors.Admin, added.Value, 1, "US", null, true, asOf)).Success);
        Assert.False((await svc.UpdateCostAsync(actors.Admin, Guid.NewGuid(), 1, "USD", null, true, asOf)).Success);
        Assert.True((await svc.UpdateCostAsync(actors.Admin, added.Value, 120, " usd ", asOf.AddDays(9), true, asOf.AddDays(-400))).Success);
        Assert.True((await svc.UpdateCostAsync(actors.Admin, added.Value, 120, "usd", null, false, asOf)).Success);
        Assert.True((await svc.UpdateCostAsync(actors.Admin, added.Value, null, "usd", null, false, asOf)).Success);
        Assert.True((await svc.UpdateCostAsync(actors.Admin, added.Value, 5, "usd", null, true, asOf.AddDays(-400))).Success);

        var listed = await svc.ListAsync(asOf);
        Assert.True(listed.Single(r => r.Id == added.Value).Stale);
        Assert.Equal(listed.Where(r => r.AnnualCostPerSeat is null).Count(), listed.TakeWhile(r => r.AnnualCostPerSeat is null).Count());

        Assert.True((await svc.RemoveAsync(actors.Viewer, added.Value)).WasDenied);
        Assert.False((await svc.RemoveAsync(actors.Admin, Guid.NewGuid())).Value);
        Assert.True((await svc.RemoveAsync(actors.Admin, added.Value)).Value);
    }
}
