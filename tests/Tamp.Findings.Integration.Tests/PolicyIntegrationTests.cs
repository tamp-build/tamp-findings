using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Policy;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Risk;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Integration.Tests;

// The policy library and the gates editor (TFND-104 … TFND-106).
//
// A risk policy is the definition of what "bad" means on this instance, and a
// gate is the release contract. Both are edits with consequences somebody else
// will feel, which is why almost every test here is about refusing something.
[Collection(DatabaseCollection.Name)]
public class PolicyIntegrationTests
{
    private readonly DatabaseFixture _fx;

    public PolicyIntegrationTests(DatabaseFixture fx) => _fx = fx;

    // ---- Library ------------------------------------------------------------

    [SkippableFact]
    public async Task A_policy_card_counts_what_uses_it()
    {
        Skip.IfNot(_fx.Available);

        // The count is what blocks deletion, so it is on the card rather than
        // something the delete dialog discovers late.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var policies = scope.ServiceProvider.GetRequiredService<PolicyService>();

        var card = (await policies.LibraryAsync()).Single(c => c.Id == world.PolicyId);

        Assert.Equal(1, card.ProjectCount);
        Assert.Equal(1, card.UseCount);
    }

    [SkippableFact]
    public async Task Loading_a_policy_hands_back_a_copy_the_editor_cannot_leak_through()
    {
        Skip.IfNot(_fx.Available);

        // A half-edited policy reaching a score would be silent.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var policies = scope.ServiceProvider.GetRequiredService<PolicyService>();

        var first = await policies.LoadAsync(world.PolicyId);
        first!.Config.Categories[RiskCategoryNames.Cve].Max = 999;

        var second = await policies.LoadAsync(world.PolicyId);

        Assert.NotEqual(999, second!.Config.Categories[RiskCategoryNames.Cve].Max);
    }

    // ---- Saving -------------------------------------------------------------

    [SkippableFact]
    public async Task A_system_policy_is_refused_even_when_the_caller_may_edit_policies()
    {
        Skip.IfNot(_fx.Available);

        // The editor disables its inputs; this refuses regardless, because a
        // disabled input is a courtesy and this is the rule.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var policies = scope.ServiceProvider.GetRequiredService<PolicyService>();

        var detail = await policies.LoadAsync(world.SeededPolicyId);
        var result = await policies.SaveAsync(
            world.Admin, world.SeededPolicyId, detail!.Config, detail.Name, detail.Description);

        Assert.False(result.Success);
        Assert.False(result.WasDenied);
        Assert.Contains("Duplicate", result.Error!, StringComparison.OrdinalIgnoreCase);
    }

    [SkippableFact]
    public async Task A_policy_with_every_category_disabled_is_refused()
    {
        Skip.IfNot(_fx.Available);

        // Every project would score 0, and a zero nobody measured reads like a
        // clean result.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var policies = scope.ServiceProvider.GetRequiredService<PolicyService>();

        var detail = await policies.LoadAsync(world.PolicyId);
        foreach (var category in detail!.Config.Categories.Values) category.Enabled = false;

        var result = await policies.SaveAsync(
            world.Admin, world.PolicyId, detail.Config, detail.Name, detail.Description);

        Assert.False(result.Success);
    }

    [SkippableFact]
    public async Task Bands_that_do_not_ascend_are_refused()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var policies = scope.ServiceProvider.GetRequiredService<PolicyService>();

        var detail = await policies.LoadAsync(world.PolicyId);
        detail!.Config.Bands.GreenMax = 60;
        detail.Config.Bands.YellowMax = 20;

        var result = await policies.SaveAsync(
            world.Admin, world.PolicyId, detail.Config, detail.Name, detail.Description);

        Assert.False(result.Success);
    }

    [SkippableFact]
    public async Task A_weight_change_is_audited_as_a_risk_decision()
    {
        Skip.IfNot(_fx.Available);

        // It moves every score under this policy — exactly what an assessor
        // reads first.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var policies = scope.ServiceProvider.GetRequiredService<PolicyService>();
        var db = _fx.Db(scope);

        var detail = await policies.LoadAsync(world.PolicyId);
        detail!.Config.Categories[RiskCategoryNames.Cve].Max += 5;
        await policies.SaveAsync(world.Admin, world.PolicyId, detail.Config, detail.Name, detail.Description);

        var entry = db.AuditEntries.Single(a => a.SubjectId == world.PolicyId && a.Action == "policy.saved");

        Assert.Equal(AuditClass.Risk, entry.Class);
    }

    // ---- Duplicate ----------------------------------------------------------

    [SkippableFact]
    public async Task A_copy_is_never_the_default_and_never_seeded()
    {
        Skip.IfNot(_fx.Available);

        // Inheriting either would silently move every project with no explicit
        // policy onto an untested one.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var policies = scope.ServiceProvider.GetRequiredService<PolicyService>();
        var db = _fx.Db(scope);

        var created = await policies.DuplicateAsync(
            world.Admin, world.SeededPolicyId, $"copy-{Guid.NewGuid():N}");

        var copy = await db.RiskPolicies.SingleAsync(p => p.Id == created.Value);

        Assert.False(copy.IsDefault);
        Assert.False(copy.IsSeeded);
    }

    [SkippableFact]
    public async Task A_copy_of_a_system_policy_is_editable()
    {
        Skip.IfNot(_fx.Available);

        // The whole escape hatch: duplicate, then edit the copy.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var policies = scope.ServiceProvider.GetRequiredService<PolicyService>();

        var created = await policies.DuplicateAsync(
            world.Admin, world.SeededPolicyId, $"copy-{Guid.NewGuid():N}");

        var detail = await policies.LoadAsync(created.Value);
        detail!.Config.Categories[RiskCategoryNames.Cve].Max += 1;

        var saved = await policies.SaveAsync(
            world.Admin, created.Value, detail.Config, detail.Name, detail.Description);

        Assert.True(saved.Success);
    }

    // ---- Delete -------------------------------------------------------------

    [SkippableFact]
    public async Task A_policy_still_in_use_cannot_be_deleted_without_saying_where_projects_go()
    {
        Skip.IfNot(_fx.Available);

        // Cascading would silently move projects onto the default and change
        // their scores with no record of why.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var policies = scope.ServiceProvider.GetRequiredService<PolicyService>();

        var result = await policies.DeleteAsync(world.Admin, world.PolicyId);

        Assert.False(result.Success);
        Assert.Contains("move them", result.Error!, StringComparison.OrdinalIgnoreCase);
    }

    [SkippableFact]
    public async Task Deleting_with_a_destination_moves_the_projects_and_says_so()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var policies = scope.ServiceProvider.GetRequiredService<PolicyService>();
        var db = _fx.Db(scope);

        var result = await policies.DeleteAsync(world.Admin, world.PolicyId, world.SeededPolicyId);

        Assert.True(result.Success);
        var project = await db.Projects.SingleAsync(p => p.Id == world.ProjectId);
        Assert.Equal(world.SeededPolicyId, project.RiskPolicyId);

        var entry = db.AuditEntries.Single(a => a.SubjectId == world.PolicyId && a.Action == "policy.deleted");
        Assert.Contains("moved 1", entry.Detail!, StringComparison.Ordinal);
    }

    // ---- Preview ------------------------------------------------------------

    [SkippableFact]
    public async Task A_preview_scores_both_configs_against_the_same_evidence()
    {
        Skip.IfNot(_fx.Available);

        // Rebuilding inputs per config would let an unrelated ingest between
        // the two calls masquerade as an effect of the weight change.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var policies = scope.ServiceProvider.GetRequiredService<PolicyService>();

        var detail = await policies.LoadAsync(world.PolicyId);
        var unchanged = await policies.PreviewAsync(world.PolicyId, detail!.Config);

        var row = unchanged.Single(r => r.ProjectId == world.ProjectId);
        Assert.Equal(row.Before, row.After);
        Assert.False(row.BandChanged);
    }

    [SkippableFact]
    public async Task A_project_with_no_build_previews_as_unscored_rather_than_as_zero()
    {
        Skip.IfNot(_fx.Available);

        // A zero nobody measured reads like a clean result.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var policies = scope.ServiceProvider.GetRequiredService<PolicyService>();

        var detail = await policies.LoadAsync(world.PolicyId);
        var rows = await policies.PreviewAsync(world.PolicyId, detail!.Config);

        Assert.Null(rows.Single(r => r.ProjectId == world.ProjectId).Before);
    }

    // ---- Gates --------------------------------------------------------------

    [SkippableFact]
    public async Task Every_well_known_gate_is_offered_even_when_nothing_is_configured()
    {
        Skip.IfNot(_fx.Available);

        // Deriving the list from stored config would mean a gate nobody has
        // enabled yet is a gate nobody can enable.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var gates = scope.ServiceProvider.GetRequiredService<GateService>();

        var rows = await gates.ListAsync(world.ProjectId);

        Assert.Equal(GateEvaluator.WellKnownGateKeys.Length, rows.Count);
        Assert.All(rows, r => Assert.False(r.Enabled));
    }

    [SkippableFact]
    public async Task Every_gate_carries_a_label_and_a_description()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var gates = scope.ServiceProvider.GetRequiredService<GateService>();

        var rows = await gates.ListAsync(world.ProjectId);

        Assert.All(rows, r =>
        {
            Assert.NotEqual(r.Key, r.Label);
            Assert.DoesNotContain("No description registered", r.Description, StringComparison.Ordinal);
        });
    }

    [SkippableFact]
    public async Task Turning_a_gate_off_is_audited_as_a_risk_decision_naming_the_gate()
    {
        Skip.IfNot(_fx.Available);

        // Loosening a gate is indistinguishable in its effect from fixing the
        // thing the gate was catching, so it has to be readable afterwards.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var gates = scope.ServiceProvider.GetRequiredService<GateService>();
        var db = _fx.Db(scope);

        var rows = (await gates.ListAsync(world.ProjectId)).ToList();
        var index = rows.FindIndex(r => r.Key == GateKeys.CriticalDast);
        rows[index] = rows[index].With(true);
        await gates.SaveAsync(world.Admin, world.Scope, world.ProjectId, rows);

        rows[index] = rows[index].With(false);
        await gates.SaveAsync(world.Admin, world.Scope, world.ProjectId, rows);

        var entry = db.AuditEntries
            .Where(a => a.ProjectId == world.ProjectId && a.Action == "gate.changed")
            .OrderByDescending(a => a.At)
            .First();

        Assert.Equal(AuditClass.Risk, entry.Class);
        Assert.Contains("criticalDast DISABLED", entry.Detail!, StringComparison.Ordinal);
    }

    [SkippableFact]
    public async Task A_save_that_changes_nothing_writes_no_audit_entry()
    {
        Skip.IfNot(_fx.Available);

        // An entry saying nothing changed dilutes the log an assessor reads
        // first.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var gates = scope.ServiceProvider.GetRequiredService<GateService>();
        var db = _fx.Db(scope);

        var rows = await gates.ListAsync(world.ProjectId);
        var result = await gates.SaveAsync(world.Admin, world.Scope, world.ProjectId, rows.ToList());

        Assert.True(result.Success);
        Assert.Equal(0, result.Value);
        Assert.Empty(db.AuditEntries.Where(a => a.ProjectId == world.ProjectId && a.Action == "gate.changed"));
    }

    [SkippableFact]
    public async Task A_threshold_survives_the_gate_being_switched_off_and_on()
    {
        Skip.IfNot(_fx.Available);

        // Someone tuned it. Dropping it on disable would make them tune it
        // again for no reason.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var gates = scope.ServiceProvider.GetRequiredService<GateService>();

        var rows = (await gates.ListAsync(world.ProjectId)).ToList();
        var index = rows.FindIndex(r => r.Key == GateKeys.CoverageRegression);
        rows[index] = rows[index].With(true).With(5d);
        await gates.SaveAsync(world.Admin, world.Scope, world.ProjectId, rows);

        rows = (await gates.ListAsync(world.ProjectId)).ToList();
        rows[index] = rows[index].With(false);
        await gates.SaveAsync(world.Admin, world.Scope, world.ProjectId, rows);

        var after = await gates.ListAsync(world.ProjectId);
        Assert.Equal(5d, after.Single(r => r.Key == GateKeys.CoverageRegression).Threshold);
    }

    [SkippableFact]
    public async Task A_lead_dev_may_not_edit_gates()
    {
        Skip.IfNot(_fx.Available);

        // Gates are the release contract — Admin and InfoSec only.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var gates = scope.ServiceProvider.GetRequiredService<GateService>();

        var rows = (await gates.ListAsync(world.ProjectId)).ToList();
        rows[0] = rows[0].With(true);

        var result = await gates.SaveAsync(world.LeadDev, world.Scope, world.ProjectId, rows);

        Assert.True(result.WasDenied);
    }

    [SkippableFact]
    public async Task A_boolean_gate_never_stores_a_threshold()
    {
        Skip.IfNot(_fx.Available);

        // A boolean gate with a stored threshold invites someone to set one and
        // believe it did something.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var gates = scope.ServiceProvider.GetRequiredService<GateService>();

        var rows = (await gates.ListAsync(world.ProjectId)).ToList();
        var index = rows.FindIndex(r => r.Key == GateKeys.KevExposure);
        Assert.False(rows[index].HasThreshold);

        rows[index] = rows[index].With(true).With(7d);
        await gates.SaveAsync(world.Admin, world.Scope, world.ProjectId, rows);

        var after = await gates.ListAsync(world.ProjectId);
        Assert.Null(after.Single(r => r.Key == GateKeys.KevExposure).Threshold);
    }

    // ---- Seed ---------------------------------------------------------------

    private sealed record World(
        Guid ProjectId, Guid PolicyId, Guid SeededPolicyId, ScopeTarget Scope,
        Principal Admin, Principal LeadDev);

    private async Task<World> SeedAsync()
    {
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);

        var suffix = Guid.NewGuid().ToString("N")[..8];

        var custom = new RiskPolicy
        {
            Name = $"pol-custom-{suffix}",
            Config = RiskPolicyDefaults.BuildTampFederalV1(),
        };
        var seeded = new RiskPolicy
        {
            Name = $"pol-system-{suffix}",
            IsSeeded = true,
            Config = RiskPolicyDefaults.BuildTampStandardV1(),
        };
        db.RiskPolicies.AddRange(custom, seeded);

        var client = new Client { Name = $"pol-client-{suffix}" };
        var project = new Project
        {
            ClientId = client.Id, Name = $"pol-project-{suffix}", RiskPolicyId = custom.Id,
        };
        db.Clients.Add(client);
        db.Projects.Add(project);

        var user = new User
        {
            Login = $"pol-{suffix}",
            DisplayName = "Policy Author",
            Email = $"pol-{suffix}@example.test",
            IsApproved = true,
        };
        db.Users.Add(user);

        await db.SaveChangesAsync();

        var target = ScopeTarget.Project(client.Id, project.Id);
        return new World(
            project.Id, custom.Id, seeded.Id, target,
            Admin: Principal.For(user.Id, user.Login, isAdmin: true, []),
            LeadDev: Principal.For(user.Id, user.Login, isAdmin: false, [ProjectRole.LeadDev]));
    }
}
