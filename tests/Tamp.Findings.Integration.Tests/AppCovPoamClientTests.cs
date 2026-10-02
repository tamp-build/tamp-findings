using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Poam;
using Tamp.Findings.Application.Projects;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Integration.Tests;

// PoamService (create/edit/transition/accept/extend/delete) and ClientQuery (visibility + save).
[Collection(DatabaseCollection.Name)]
public class AppCovPoamClientTests
{
    private readonly DatabaseFixture _fx;
    public AppCovPoamClientTests(DatabaseFixture fx) => _fx = fx;

    private static PoamDraft Draft(string title = "weak", PoamStatus status = PoamStatus.Open, string? url = null, DateTimeOffset? due = null) =>
        new(title, "desc", " plan ", " ", url, Severity.High, status, due, [Guid.Empty, Guid.Empty]);

    private async Task WithSodAsync(bool enforce, Func<Task> body)
    {
        bool? original = null;
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            var row = await db.InstanceSettings.SingleOrDefaultAsync(x => x.Id == InstanceSettings.SingletonId);
            if (row is null) { row = new InstanceSettings(); db.InstanceSettings.Add(row); }
            else original = row.EnforceSeparationOfDuties;
            row.EnforceSeparationOfDuties = enforce;
            await db.SaveChangesAsync();
        }
        try { await body(); }
        finally
        {
            using var scope = _fx.Scope();
            var db = _fx.Db(scope);
            var row = await db.InstanceSettings.SingleAsync(x => x.Id == InstanceSettings.SingletonId);
            if (original is null) db.InstanceSettings.Remove(row); else row.EnforceSeparationOfDuties = original.Value;
            await db.SaveChangesAsync();
        }
    }

    [SkippableFact]
    public async Task Poam_lifecycle_with_capability_and_validation_rules()
    {
        Skip.IfNot(_fx.Available);
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var actors = await AppCovSeed.UsersAsync(db);
        var (client, project) = await AppCovSeed.ClientProjectAsync(db, "poam");
        var target = ScopeTarget.Project(client.Id, project.Id);
        var svc = scope.ServiceProvider.GetRequiredService<PoamService>();

        Assert.True((await svc.CreateAsync(actors.Viewer, target, project.Id, Draft())).WasDenied);
        Assert.False((await svc.CreateAsync(actors.Lead, target, project.Id, Draft(" "))).Success);
        Assert.False((await svc.CreateAsync(actors.Lead, target, project.Id, Draft() with { WeaknessDescription = " " })).Success);
        Assert.False((await svc.CreateAsync(actors.Lead, target, project.Id, Draft(url: "not a url"))).Success);

        var created = await svc.CreateAsync(actors.Lead, target, project.Id, Draft(url: "https://example.test/x", due: DateTimeOffset.UtcNow.AddDays(5)));
        Assert.True(created.Success);
        var id = created.Value;
        var born = await svc.CreateAsync(actors.Lead, target, project.Id, Draft("born done", PoamStatus.Completed));
        var stored = await db.PoamItems.AsNoTracking().SingleAsync(p => p.Id == born.Value);
        Assert.NotNull(stored.ClosedAt);
        Assert.NotNull(stored.ActualCompletionDate);
        var cancelled = await svc.CreateAsync(actors.Lead, target, project.Id, Draft("born cancelled", PoamStatus.Cancelled));
        var storedC = await db.PoamItems.AsNoTracking().SingleAsync(p => p.Id == cancelled.Value);
        Assert.NotNull(storedC.ClosedAt);
        Assert.Null(storedC.ActualCompletionDate);

        // update
        Assert.True((await svc.UpdateAsync(actors.Viewer, target, project.Id, id, Draft("v2"))).WasDenied);
        Assert.False((await svc.UpdateAsync(actors.Lead, target, project.Id, id, Draft(" "))).Success);
        Assert.False((await svc.UpdateAsync(actors.Lead, target, project.Id, Guid.NewGuid(), Draft("v2"))).Success);
        Assert.False((await svc.UpdateAsync(actors.Lead, target, project.Id, id, Draft("v2", PoamStatus.Completed))).Success);
        Assert.True((await svc.UpdateAsync(actors.Lead, target, project.Id, id, Draft("v2", url: "https://x.test"))).Success);

        // transitions
        Assert.False((await svc.TransitionAsync(actors.InfoSec, target, project.Id, id, PoamStatus.RiskAccepted)).Success);
        Assert.True((await svc.TransitionAsync(actors.Viewer, target, project.Id, id, PoamStatus.InProgress)).WasDenied);
        Assert.True((await svc.TransitionAsync(actors.Viewer, target, project.Id, id, PoamStatus.Completed)).WasDenied);
        Assert.False((await svc.TransitionAsync(actors.Lead, target, project.Id, Guid.NewGuid(), PoamStatus.InProgress)).Success);
        Assert.True((await svc.TransitionAsync(actors.Lead, target, project.Id, id, PoamStatus.InProgress)).Success);
        Assert.True((await svc.TransitionAsync(actors.Lead, target, project.Id, id, PoamStatus.InProgress)).Success);
        Assert.True((await svc.TransitionAsync(actors.Lead, target, project.Id, id, PoamStatus.Completed)).Success);
        Assert.True((await svc.TransitionAsync(actors.Lead, target, project.Id, id, PoamStatus.Open)).Success);
        Assert.Null((await db.PoamItems.AsNoTracking().SingleAsync(p => p.Id == id)).ClosedAt);

        // extension
        var newDate = DateTimeOffset.UtcNow.AddDays(30);
        Assert.True((await svc.RequestExtensionAsync(actors.Viewer, target, project.Id, id, newDate, "why")).WasDenied);
        Assert.False((await svc.RequestExtensionAsync(actors.Lead, target, project.Id, id, newDate, "  ")).Success);
        Assert.False((await svc.RequestExtensionAsync(actors.Lead, target, project.Id, Guid.NewGuid(), newDate, "why")).Success);
        Assert.True((await svc.RequestExtensionAsync(actors.Lead, target, project.Id, id, newDate, "vendor delay")).Success);

        // delete
        Assert.True((await svc.DeleteAsync(actors.Viewer, target, project.Id, id)).WasDenied);
        Assert.False((await svc.DeleteAsync(actors.Lead, target, project.Id, Guid.NewGuid())).Value);
        Assert.True((await svc.DeleteAsync(actors.Lead, target, project.Id, id)).Value);
        Assert.NotEmpty(await db.AuditEntries.AsNoTracking().Where(a => a.Action == "poam.deleted" && a.SubjectId == id).ToListAsync());
    }

    [SkippableFact]
    public async Task Direct_risk_acceptance_requires_signature_and_no_separation_of_duties()
    {
        Skip.IfNot(_fx.Available);
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var actors = await AppCovSeed.UsersAsync(db);
        var (client, project) = await AppCovSeed.ClientProjectAsync(db, "poam-ra");
        var target = ScopeTarget.Project(client.Id, project.Id);
        var svc = scope.ServiceProvider.GetRequiredService<PoamService>();
        var item = (await svc.CreateAsync(actors.Lead, target, project.Id, Draft("ra"))).Value;

        Assert.True((await svc.AcceptRiskDirectlyAsync(actors.Lead, target, project.Id, item, actors.Lead.Login)).WasDenied);

        await WithSodAsync(true, async () =>
        {
            using var s = _fx.Scope();
            var p = s.ServiceProvider.GetRequiredService<PoamService>();
            Assert.True(await p.RiskAcceptanceRequiresApprovalAsync());
            Assert.False((await p.AcceptRiskDirectlyAsync(actors.InfoSec, target, project.Id, item, actors.InfoSec.Login)).Success);
        });

        await WithSodAsync(false, async () =>
        {
            using var s = _fx.Scope();
            var p = s.ServiceProvider.GetRequiredService<PoamService>();
            Assert.False(await p.RiskAcceptanceRequiresApprovalAsync());
            Assert.False((await p.AcceptRiskDirectlyAsync(actors.InfoSec, target, project.Id, item, "someone else")).Success);
            Assert.False((await p.AcceptRiskDirectlyAsync(actors.InfoSec, target, project.Id, Guid.NewGuid(), actors.InfoSec.Login)).Success);
            Assert.True((await p.AcceptRiskDirectlyAsync(actors.InfoSec, target, project.Id, item, actors.InfoSec.Login.ToUpperInvariant())).Success);
            // idempotent once accepted
            Assert.True((await p.AcceptRiskDirectlyAsync(actors.InfoSec, target, project.Id, item, actors.InfoSec.Login)).Success);
        });

        var row = await db.PoamItems.AsNoTracking().SingleAsync(p => p.Id == item);
        Assert.Equal(PoamStatus.RiskAccepted, row.Status);
        Assert.Null(row.ActualCompletionDate);
        Assert.NotNull(row.ClosedAt);
    }

    [SkippableFact]
    public async Task Client_query_respects_visibility_and_orders_projects()
    {
        Skip.IfNot(_fx.Available);
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var (client, p1) = await AppCovSeed.ClientProjectAsync(db, "cq");
        var p2 = new Project { ClientId = client.Id, Name = $"cq-second-{Guid.NewGuid():N}" };
        var p3 = new Project { ClientId = client.Id, Name = $"cq-never-{Guid.NewGuid():N}" };
        var policy = new RiskPolicy { Name = $"cq-pol-{Guid.NewGuid():N}", Config = new RiskPolicyConfig() };
        db.RiskPolicies.Add(policy);
        p2.RiskPolicyId = policy.Id;
        db.Projects.AddRange(p2, p3);
        (await db.Clients.FindAsync(client.Id))!.RiskPolicyId = policy.Id;
        (await db.Clients.FindAsync(client.Id))!.Description = "desc";
        await db.SaveChangesAsync();
        await AppCovSeed.BuildAsync(db, p1.Id);
        await AppCovSeed.BuildAsync(db, p1.Id);
        await AppCovSeed.BuildAsync(db, p2.Id);

        var q = scope.ServiceProvider.GetRequiredService<ClientQuery>();
        Assert.Null(await q.LoadAsync("nope-" + Guid.NewGuid(), VisibleSet.Everything));
        var all = (await q.LoadAsync(client.Name.ToUpperInvariant(), VisibleSet.Everything))!;
        Assert.Equal(3, all.Projects.Count);
        Assert.Equal(policy.Name, all.RiskPolicyName);
        Assert.Null(all.Projects[0].LastBuild);
        Assert.Equal(2, all.Projects.Single(p => p.Id == p1.Id).Builds);
        Assert.True(all.Projects.Single(p => p.Id == p1.Id).InheritsPolicy);
        Assert.False(all.Projects.Single(p => p.Id == p2.Id).InheritsPolicy);

        Assert.Null(await q.LoadAsync(client.Name, VisibleSet.Nothing));
        var viaProject = new VisibleSet(false, new HashSet<Guid>(), new HashSet<Guid> { p1.Id });
        var narrowed = (await q.LoadAsync(client.Name, viaProject))!;
        Assert.Single(narrowed.Projects);
        var viaClient = new VisibleSet(false, new HashSet<Guid> { client.Id }, new HashSet<Guid>());
        Assert.Equal(3, (await q.LoadAsync(client.Name, viaClient))!.Projects.Count);
    }

    [SkippableFact]
    public async Task Client_save_validates_and_audits()
    {
        Skip.IfNot(_fx.Available);
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var actors = await AppCovSeed.UsersAsync(db);
        var (client, _) = await AppCovSeed.ClientProjectAsync(db, "cs");
        var (other, _) = await AppCovSeed.ClientProjectAsync(db, "cs-other");
        var policy = new RiskPolicy { Name = $"cs-pol-{Guid.NewGuid():N}", Config = new RiskPolicyConfig() };
        db.RiskPolicies.Add(policy);
        await db.SaveChangesAsync();
        var q = scope.ServiceProvider.GetRequiredService<ClientQuery>();

        Assert.True((await q.SaveAsync(actors.Viewer, client.Id, "x", null, null)).WasDenied);
        Assert.False((await q.SaveAsync(actors.Admin, Guid.NewGuid(), "x", null, null)).Success);
        Assert.False((await q.SaveAsync(actors.Admin, client.Id, "  ", null, null)).Success);
        Assert.False((await q.SaveAsync(actors.Admin, client.Id, other.Name.ToUpperInvariant(), null, null)).Success);
        Assert.False((await q.SaveAsync(actors.Admin, client.Id, client.Name, null, Guid.NewGuid())).Success);

        var renamed = $"{client.Name}-renamed";
        Assert.True((await q.SaveAsync(actors.Admin, client.Id, renamed, "  hello ", null)).Success);
        Assert.True((await q.SaveAsync(actors.Admin, client.Id, renamed, "", policy.Id)).Success);
        Assert.True((await q.SaveAsync(actors.Admin, client.Id, renamed, null, policy.Id)).Success);
        var row = await db.Clients.AsNoTracking().SingleAsync(c => c.Id == client.Id);
        Assert.Equal(renamed, row.Name);
        Assert.Null(row.Description);
        Assert.Equal(policy.Id, row.RiskPolicyId);
        var audits = await db.AuditEntries.AsNoTracking().Where(a => a.SubjectId == client.Id && a.Action == "client.updated").ToListAsync();
        Assert.Equal(3, audits.Count);
        Assert.Contains(audits, a => a.Class == AuditClass.Risk);
        Assert.Contains(audits, a => a.Class == AuditClass.Other);
    }
}
