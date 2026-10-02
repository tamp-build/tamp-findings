using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Policy;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Risk;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Integration.Tests;

// PolicyService (library/save/duplicate/delete/preview) and GateService (list/save/describe).
[Collection(DatabaseCollection.Name)]
public class AppCovPolicyGateServicesTests
{
    private readonly DatabaseFixture _fx;
    public AppCovPolicyGateServicesTests(DatabaseFixture fx) => _fx = fx;

    private static RiskPolicyConfig Config(double sastMax = 20) => new()
    {
        Categories = new()
        {
            [RiskCategoryNames.Cve] = new RiskCategoryConfig { Enabled = true, Max = 40, Weights = new() { ["critical"] = 1 } },
            ["sastSevere"] = new RiskCategoryConfig { Enabled = true, Max = sastMax },
            ["off"] = new RiskCategoryConfig { Enabled = false, Max = 5 },
        },
    };

    private async Task<Guid> NewPolicyAsync(string tag, bool seeded = false, bool isDefault = false)
    {
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var p = new RiskPolicy { Name = $"cov-{tag}-{Guid.NewGuid():N}", Config = Config(), IsSeeded = seeded, IsDefault = isDefault };
        db.RiskPolicies.Add(p);
        await db.SaveChangesAsync();
        return p.Id;
    }

    [SkippableFact]
    public async Task Policy_save_validation_duplicate_delete_and_library()
    {
        Skip.IfNot(_fx.Available);
        var id = await NewPolicyAsync("pol");
        var seeded = await NewPolicyAsync("seed", seeded: true);
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var actors = await AppCovSeed.UsersAsync(db);
        var svc = scope.ServiceProvider.GetRequiredService<PolicyService>();

        var detail = (await svc.LoadAsync(id))!;
        Assert.Null(await svc.LoadAsync(Guid.NewGuid()));
        Assert.Equal(3, detail.Config.Categories.Count);

        Assert.True((await svc.SaveAsync(actors.Viewer, id, Config(), "n", null)).WasDenied);
        Assert.False((await svc.SaveAsync(actors.Admin, Guid.NewGuid(), Config(), "n", null)).Success);
        Assert.Contains("read-only", (await svc.SaveAsync(actors.Admin, seeded, Config(), "n", null)).Error);
        Assert.False((await svc.SaveAsync(actors.Admin, id, new RiskPolicyConfig { SchemaVersion = 99, Categories = Config().Categories }, "n", null)).Success);
        var negative = Config(); negative.Categories["sastSevere"].Max = -1;
        Assert.False((await svc.SaveAsync(actors.Admin, id, negative, "n", null)).Success);
        Assert.False((await svc.SaveAsync(actors.Admin, id, new RiskPolicyConfig(), "n", null)).Success);
        var badBands = Config(); badBands.Bands = new RiskBands { GreenMax = 30, YellowMax = 20, OrangeMax = 50 };
        Assert.False((await svc.SaveAsync(actors.Admin, id, badBands, "n", null)).Success);
        Assert.False((await svc.SaveAsync(actors.Admin, id, Config(), "  ", null)).Success);

        var other = await NewPolicyAsync("other");
        var otherName = (await db.RiskPolicies.AsNoTracking().SingleAsync(p => p.Id == other)).Name;
        Assert.False((await svc.SaveAsync(actors.Admin, id, Config(), otherName.ToUpperInvariant(), null)).Success);
        var newName = $"cov-renamed-{Guid.NewGuid():N}";
        Assert.True((await svc.SaveAsync(actors.Admin, id, Config(25), newName, "  desc ")).Success);
        Assert.True((await svc.SaveAsync(actors.Admin, id, Config(25), newName, " ")).Success);
        Assert.Null((await svc.LoadAsync(id))!.Description);

        // duplicate
        Assert.True((await svc.DuplicateAsync(actors.Viewer, id, "x")).WasDenied);
        Assert.False((await svc.DuplicateAsync(actors.Admin, Guid.NewGuid(), "x")).Success);
        Assert.False((await svc.DuplicateAsync(actors.Admin, id, " ")).Success);
        Assert.False((await svc.DuplicateAsync(actors.Admin, id, newName.ToUpperInvariant())).Success);
        var copy = await svc.DuplicateAsync(actors.Admin, seeded, $"cov-copy-{Guid.NewGuid():N}");
        Assert.True(copy.Success);
        var copied = await db.RiskPolicies.AsNoTracking().SingleAsync(p => p.Id == copy.Value);
        Assert.False(copied.IsSeeded);
        Assert.False(copied.IsDefault);

        // library counts usage
        var (client, project) = await AppCovSeed.ClientProjectAsync(db, "pol-use");
        (await db.Projects.FindAsync(project.Id))!.RiskPolicyId = copy.Value;
        (await db.Clients.FindAsync(client.Id))!.RiskPolicyId = copy.Value;
        await db.SaveChangesAsync();
        var card = (await svc.LibraryAsync()).Single(c => c.Id == copy.Value);
        Assert.Equal(1, card.ProjectCount);
        Assert.Equal(1, card.ClientCount);
        Assert.Equal(2, card.UseCount);
        Assert.Equal(2, card.EnabledCategories);

        // delete
        Assert.True((await svc.DeleteAsync(actors.Viewer, copy.Value)).WasDenied);
        Assert.False((await svc.DeleteAsync(actors.Admin, Guid.NewGuid())).Value);
        Assert.False((await svc.DeleteAsync(actors.Admin, copy.Value)).Success);
        Assert.False((await svc.DeleteAsync(actors.Admin, copy.Value, Guid.NewGuid())).Success);
        Assert.True((await svc.DeleteAsync(actors.Admin, copy.Value, other)).Value);
        Assert.Equal(other, (await db.Projects.AsNoTracking().SingleAsync(p => p.Id == project.Id)).RiskPolicyId);
        Assert.True((await svc.DeleteAsync(actors.Admin, other, id)).Value);

        var def = await db.RiskPolicies.AsNoTracking().Where(p => p.IsDefault).Select(p => (Guid?)p.Id).FirstOrDefaultAsync();
        if (def is { } defId)
            Assert.Contains("instance default", (await svc.DeleteAsync(actors.Admin, defId)).Error);
    }

    [SkippableFact]
    public async Task Policy_preview_rescoring_orders_band_changes_first()
    {
        Skip.IfNot(_fx.Available);
        var id = await NewPolicyAsync("prev");
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var svc = scope.ServiceProvider.GetRequiredService<PolicyService>();
        var (client, noBuild) = await AppCovSeed.ClientProjectAsync(db, "prev-none");
        var heavy = new Project { ClientId = client.Id, Name = $"prev-heavy-{Guid.NewGuid():N}", RiskPolicyId = id };
        var viaClient = new Project { ClientId = client.Id, Name = $"prev-client-{Guid.NewGuid():N}" };
        db.Projects.AddRange(heavy, viaClient);
        (await db.Projects.FindAsync(noBuild.Id))!.RiskPolicyId = id;
        (await db.Clients.FindAsync(client.Id))!.RiskPolicyId = id;
        await db.SaveChangesAsync();

        var cv = await AppCovSeed.BuildAsync(db, heavy.Id);
        await AppCovSeed.BuildAsync(db, viaClient.Id);
        var snap = new SbomSnapshot { ComponentVersionId = cv.Id };
        db.SbomSnapshots.Add(snap);
        var comp = new SbomComponent { SbomSnapshotId = snap.Id, Purl = $"pkg:nuget/p.{heavy.Id:N}@1", Name = "p", Version = "1" };
        db.SbomComponents.Add(comp);
        for (var i = 0; i < 6; i++)
            db.Vulnerabilities.Add(new Vulnerability { SbomComponentId = comp.Id, AdvisoryId = $"CVE-COV-{i}", Severity = Severity.Critical });
        db.ScanRunReceipts.Add(new ScanRunReceipt { ComponentVersionId = cv.Id, Scanner = ScannerKind.OsvScanner, Status = ScanRunStatus.Succeeded, StartedAt = DateTimeOffset.UtcNow, CompletedAt = DateTimeOffset.UtcNow });
        await db.SaveChangesAsync();

        Assert.Empty(await svc.PreviewAsync(Guid.NewGuid(), Config()));
        var harsher = Config(); harsher.Categories[RiskCategoryNames.Cve].Max = 90;
        var rows = await svc.PreviewAsync(id, harsher);
        Assert.Equal(3, rows.Count);
        Assert.Contains(rows, r => r.ProjectId == noBuild.Id && r.Before is null && !r.BandChanged);
        var h = rows.Single(r => r.ProjectId == heavy.Id);
        Assert.True(h.After > h.Before);
        Assert.Equal(heavy.Id, rows.Where(r => r.Before is not null).OrderByDescending(r => Math.Abs(r.After!.Value - r.Before!.Value)).First().ProjectId);
        Assert.Equal(rows.Where(r => r.BandChanged).Count(), rows.TakeWhile(r => r.BandChanged).Count());
    }

    [SkippableFact]
    public async Task Gate_service_lists_saves_and_audits_only_real_changes()
    {
        Skip.IfNot(_fx.Available);
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var actors = await AppCovSeed.UsersAsync(db);
        var (client, project) = await AppCovSeed.ClientProjectAsync(db, "gate");
        var target = ScopeTarget.Project(client.Id, project.Id);
        var svc = scope.ServiceProvider.GetRequiredService<GateService>();

        var rows = await svc.ListAsync(project.Id);
        Assert.Equal(GateEvaluator.WellKnownGateKeys.Length, rows.Count);
        Assert.All(rows, r => Assert.False(r.Enabled));
        Assert.Equal(GateEvaluator.WellKnownGateKeys.Length, (await svc.ListAsync(Guid.NewGuid())).Count);
        Assert.Null(await svc.EnforcementOverrideAsync(project.Id));
        Assert.Null(await svc.EnforcementOverrideAsync(Guid.NewGuid()));

        Assert.True((await svc.SaveAsync(actors.Viewer, target, project.Id, rows)).WasDenied);
        Assert.False((await svc.SaveAsync(actors.Admin, target, Guid.NewGuid(), rows)).Success);
        var negative = rows.Select(r => r.Key == GateKeys.CriticalCves ? r.With(true).With((double?)-1) : r).ToList();
        Assert.False((await svc.SaveAsync(actors.Admin, target, project.Id, negative)).Success);
        Assert.Equal(0, (await svc.SaveAsync(actors.Admin, target, project.Id, rows)).Value);

        var edited = rows.Select(r =>
            r.Key == GateKeys.CriticalCves ? r.With(true).With((double?)2)
            : r.Key == GateKeys.KevExposure ? r.With(true).With((double?)7)
            : r).ToList();
        Assert.Equal(2, (await svc.SaveAsync(actors.Admin, target, project.Id, edited)).Value);
        Assert.Equal(0, (await svc.SaveAsync(actors.Admin, target, project.Id, edited)).Value);

        var tuned = edited.Select(r => r.Key == GateKeys.CriticalCves ? r.With((double?)5) : r.Key == GateKeys.KevExposure ? r.With(false) : r).ToList();
        Assert.Equal(3, (await svc.SaveAsync(actors.Admin, target, project.Id, tuned, EnforcementMode.Enforcing)).Value);
        Assert.Equal(EnforcementMode.Enforcing, await svc.EnforcementOverrideAsync(project.Id));
        var cleared = await svc.SaveAsync(actors.Admin, target, project.Id, tuned, null);
        Assert.Equal(1, cleared.Value);
        var listed = await svc.ListAsync(project.Id);
        Assert.Equal(5, listed.Single(r => r.Key == GateKeys.CriticalCves).Threshold);
        Assert.Null(listed.Single(r => r.Key == GateKeys.KevExposure).Threshold);
        Assert.True(GateService.TakesThreshold(GateKeys.CriticalCves));
        Assert.False(GateService.TakesThreshold(GateKeys.SignedCommits));

        var audits = await db.AuditEntries.AsNoTracking().Where(a => a.SubjectId == project.Id && a.Action == "gate.changed").ToListAsync();
        Assert.Equal(3, audits.Count);
        Assert.Contains(audits, a => a.Detail!.Contains("DISABLED", StringComparison.Ordinal));
        Assert.Contains(audits, a => a.Detail!.Contains("enforcement inherit", StringComparison.Ordinal));
        Assert.Contains(audits, a => a.Detail!.Contains("threshold", StringComparison.Ordinal));
    }
}
