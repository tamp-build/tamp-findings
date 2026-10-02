using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Approvals;
using Tamp.Findings.Application.Licensing;
using Tamp.Findings.Application.Policy;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Risk;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Integration.Tests;

// Client/template policy services, their approval effects and the licence knowledge base.
[Collection(DatabaseCollection.Name)]
public class AppCovPolicyServicesTests
{
    private readonly DatabaseFixture _fx;
    public AppCovPolicyServicesTests(DatabaseFixture fx) => _fx = fx;

    private static PolicyLayer Strict() => new()
    {
        Mode = EnforcementMode.Enforcing,
        Gates = new() { [GateKeys.AnyCves] = new GateConfig { Enabled = true, Threshold = 0 } },
    };

    private static PolicyLayer Loose() => new()
    {
        Mode = EnforcementMode.Advisory,
        Gates = new() { [GateKeys.AnyCves] = new GateConfig { Enabled = false } },
    };

    private async Task<Guid> NewTemplateAsync(PolicyLayer layer)
    {
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var t = new PolicyTemplate { Name = $"cov-tpl-{Guid.NewGuid():N}", Layer = layer };
        db.PolicyTemplates.Add(t);
        await db.SaveChangesAsync();
        return t.Id;
    }

    [SkippableFact]
    public async Task Template_save_applies_hardening_and_routes_loosening_to_approval()
    {
        Skip.IfNot(_fx.Available);
        var tpl = await NewTemplateAsync(Strict());
        using var scope = _fx.Scope();
        var sp = scope.ServiceProvider;
        var db = _fx.Db(scope);
        var actors = await AppCovSeed.UsersAsync(db);
        var svc = sp.GetRequiredService<PolicyTemplateService>();
        var approvals = sp.GetRequiredService<ApprovalService>();

        Assert.Contains((await svc.LibraryAsync()), c => c.Id == tpl);
        Assert.NotNull(await svc.LoadAsync(tpl));
        Assert.Null(await svc.LoadAsync(Guid.NewGuid()));

        Assert.True((await svc.SaveAsync(actors.Viewer, tpl, Strict())).WasDenied);
        Assert.False((await svc.SaveAsync(actors.Admin, Guid.NewGuid(), Strict())).Success);

        var hardened = Strict();
        hardened.DeniedLicenses.Add("GPL-3.0");
        var applied = await svc.SaveAsync(actors.Admin, tpl, hardened);
        Assert.True(applied.Success);
        Assert.Equal(TemplateSaveStatus.Applied, applied.Value!.Status);
        Assert.Equal(2, (await svc.LoadAsync(tpl))!.Version);

        var routed = await svc.SaveAsync(actors.Admin, tpl, Loose(), "needed");
        Assert.True(routed.Success);
        Assert.Equal(TemplateSaveStatus.PendingApproval, routed.Value!.Status);
        Assert.NotEmpty(routed.Value!.Loosened);
        // template unchanged until approved
        Assert.Equal(2, (await svc.LoadAsync(tpl))!.Version);

        // a second identical request is refused while the first is pending
        var dup = await svc.SaveAsync(actors.Admin, tpl, Loose());
        Assert.False(dup.Success);

        var approved = await approvals.DecideAsync(actors.InfoSec, routed.Value!.Id, approve: true);
        Assert.True(approved.Success);
        var after = (await svc.LoadAsync(tpl))!;
        Assert.Equal(3, after.Version);
        Assert.Equal(EnforcementMode.Advisory, after.Layer.Mode);
    }

    [SkippableFact]
    public async Task Loosen_effect_ignores_missing_template_and_bad_payload()
    {
        Skip.IfNot(_fx.Available);
        using var scope = _fx.Scope();
        var sp = scope.ServiceProvider;
        var db = _fx.Db(scope);
        var actors = await AppCovSeed.UsersAsync(db);
        var approvals = sp.GetRequiredService<ApprovalService>();
        var tpl = await NewTemplateAsync(Strict());

        foreach (var (subject, payload) in new (Guid, string?)[] { (Guid.NewGuid(), "{}"), (tpl, null), (tpl, "not json") })
        {
            var req = await approvals.RequestAsync(actors.Admin, default, ApprovalKind.LoosenPolicyTemplate, nameof(PolicyTemplate), subject, "x", payload: payload);
            Assert.True(req.Success);
            Assert.True((await approvals.DecideAsync(actors.InfoSec, req.Value, true)).Success);
        }
        using var s2 = _fx.Scope();
        Assert.Equal(1, (await s2.ServiceProvider.GetRequiredService<PolicyTemplateService>().LoadAsync(tpl))!.Version);
    }

    [SkippableFact]
    public async Task Client_policy_load_save_and_template_switch()
    {
        Skip.IfNot(_fx.Available);
        var tplA = await NewTemplateAsync(Strict());
        var tplB = await NewTemplateAsync(new PolicyLayer());
        using var scope = _fx.Scope();
        var sp = scope.ServiceProvider;
        var db = _fx.Db(scope);
        var actors = await AppCovSeed.UsersAsync(db);
        var (client, _) = await AppCovSeed.ClientProjectAsync(db);
        var plain = (await AppCovSeed.ClientProjectAsync(db)).Client;
        (await db.Clients.FindAsync(client.Id))!.PolicyTemplateId = tplA;
        await db.SaveChangesAsync();

        var svc = sp.GetRequiredService<ClientPolicyService>();
        var approvals = sp.GetRequiredService<ApprovalService>();

        Assert.Null(await svc.LoadAsync(Guid.NewGuid()));
        var view = (await svc.LoadAsync(client.Id))!;
        Assert.Equal(client.Name, view.Name);
        Assert.Equal(tplA, view.TemplateId);
        Assert.NotNull(view.TemplateLabel);
        var plainView = (await svc.LoadAsync(plain.Id))!;
        Assert.Null(plainView.TemplateId);
        Assert.Null(plainView.TemplateLabel);

        Assert.True((await svc.SaveHardeningAsync(actors.Viewer, client.Id, Strict())).WasDenied);
        Assert.False((await svc.SaveHardeningAsync(actors.Admin, Guid.NewGuid(), Strict())).Success);
        var loosened = await svc.SaveHardeningAsync(actors.Admin, client.Id, Loose());
        Assert.False(loosened.Success);
        Assert.Contains("harden", loosened.Error);
        Assert.True((await svc.SaveHardeningAsync(actors.Admin, client.Id, Strict())).Success);
        // no template: anything is accepted
        Assert.True((await svc.SaveHardeningAsync(actors.Admin, plain.Id, Loose())).Success);

        Assert.True((await svc.RequestTemplateSwitchAsync(actors.Viewer, client.Id, tplB)).WasDenied);
        Assert.False((await svc.RequestTemplateSwitchAsync(actors.Admin, Guid.NewGuid(), tplB)).Success);
        Assert.False((await svc.RequestTemplateSwitchAsync(actors.Admin, client.Id, tplA)).Success);
        Assert.False((await svc.RequestTemplateSwitchAsync(actors.Admin, client.Id, Guid.NewGuid())).Success);
        var req = await svc.RequestTemplateSwitchAsync(actors.Admin, client.Id, tplB, "because");
        Assert.True(req.Success);
        Assert.True((await approvals.DecideAsync(actors.InfoSec, req.Value, true)).Success);
        Assert.Equal(tplB, (await svc.LoadAsync(client.Id))!.TemplateId);
    }

    [SkippableFact]
    public async Task Switch_effect_ignores_bad_targets()
    {
        Skip.IfNot(_fx.Available);
        using var scope = _fx.Scope();
        var sp = scope.ServiceProvider;
        var db = _fx.Db(scope);
        var actors = await AppCovSeed.UsersAsync(db);
        var (client, _) = await AppCovSeed.ClientProjectAsync(db);
        var approvals = sp.GetRequiredService<ApprovalService>();
        foreach (var (subject, payload) in new (Guid, string?)[] { (Guid.NewGuid(), Guid.NewGuid().ToString()), (client.Id, "nope"), (client.Id, Guid.NewGuid().ToString()) })
        {
            var req = await approvals.RequestAsync(actors.Admin, default, ApprovalKind.SwitchClientTemplate, nameof(Client), subject, "x", payload: payload);
            Assert.True((await approvals.DecideAsync(actors.InfoSec, req.Value, true)).Success);
        }
        Assert.Null((await db.Clients.AsNoTracking().SingleAsync(c => c.Id == client.Id)).PolicyTemplateId);
    }

    [SkippableFact]
    public async Task License_resolution_upsert_clear_and_map()
    {
        Skip.IfNot(_fx.Available);
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var actors = await AppCovSeed.UsersAsync(db);
        var svc = scope.ServiceProvider.GetRequiredService<LicenseResolutionService>();
        var purl = $"pkg:nuget/Cov.{Guid.NewGuid():N}@1.0.0";

        Assert.True((await svc.ResolveAsync(actors.Viewer, purl, "MIT", null)).WasDenied);
        Assert.False((await svc.ResolveAsync(actors.Admin, " ", "MIT", null)).Success);
        Assert.False((await svc.ResolveAsync(actors.Admin, purl, " ", null)).Success);
        var first = await svc.ResolveAsync(actors.Admin, purl, "MIT", "  note  ");
        Assert.True(first.Success);
        var again = await svc.ResolveAsync(actors.Admin, purl, "Apache-2.0", null);
        Assert.Equal(first.Value, again.Value);

        var map = await svc.MapAsync();
        Assert.Equal("Apache-2.0", map[purl.ToUpperInvariant()]);
        var list = await svc.ListAsync();
        Assert.Contains(list, r => r.Purl == purl && r.Note is null);

        Assert.True((await svc.ClearAsync(actors.Viewer, purl)).WasDenied);
        Assert.False((await svc.ClearAsync(actors.Admin, "pkg:none")).Success);
        Assert.True((await svc.ClearAsync(actors.Admin, purl)).Success);
        Assert.DoesNotContain(await svc.ListAsync(), r => r.Purl == purl);
    }
}
