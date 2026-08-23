using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Explorer;
using Tamp.Findings.Application.Risk;
using Tamp.Findings.Application.SystemAdmin;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Integration.Tests;

// Costs and licences (TFND-8 / F7.2, F7.3).
//
// This is the one screen in the product whose failure mode is a CONFIDENT WRONG
// NUMBER rather than a missing one: a figure here gets quoted in a planning
// meeting. So most of what these assert is about what the totals refuse to
// claim — unpriced is not zero, currencies do not add, and a package in three
// components is one obligation.
[Collection(DatabaseCollection.Name)]
public class CostsAndLicensesIntegrationTests
{
    private readonly DatabaseFixture _fx;

    public CostsAndLicensesIntegrationTests(DatabaseFixture fx) => _fx = fx;

    [SkippableFact]
    public async Task A_paid_vendor_in_the_sbom_is_matched()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var costs = scope.ServiceProvider.GetRequiredService<CostsAndLicensesQuery>();

        var data = await costs.LoadAsync(world.ProjectId, world.AsOf);

        var vendor = Assert.Single(data.Paid, p => p.Vendor == world.Vendor);
        Assert.Equal(2, vendor.Packages.Count);
        Assert.Contains("api", vendor.Components);
    }

    [SkippableFact]
    public async Task An_unpriced_product_is_counted_rather_than_treated_as_zero()
    {
        Skip.IfNot(_fx.Available);

        // The failure this screen exists to avoid. A product with no recorded
        // cost silently contributing zero would make the total read as complete
        // when it is a floor.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var costs = scope.ServiceProvider.GetRequiredService<CostsAndLicensesQuery>();

        var data = await costs.LoadAsync(world.ProjectId, world.AsOf);

        Assert.True(data.UnpricedProducts > 0);
        Assert.DoesNotContain(data.Paid.Where(p => p.Vendor == world.Vendor),
            p => p.AnnualCostPerSeat == 0m);
    }

    [SkippableFact]
    public async Task A_recorded_cost_reaches_the_total()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var registry = scope.ServiceProvider.GetRequiredService<PaidComponentRegistry>();
        var costs = scope.ServiceProvider.GetRequiredService<CostsAndLicensesQuery>();

        var saved = await registry.UpdateCostAsync(
            world.Admin, world.RegistryId, 1200m, "usd", null, enabled: true, world.AsOf);
        Assert.True(saved.Success);

        var data = await costs.LoadAsync(world.ProjectId, world.AsOf);

        Assert.Equal(1200m, data.AnnualPerSeatByCurrency["USD"]);
    }

    [SkippableFact]
    public async Task Currencies_are_reported_separately_rather_than_summed()
    {
        Skip.IfNot(_fx.Available);

        // Adding USD to EUR because both are numbers is exactly the error a
        // budget screen must not make.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var registry = scope.ServiceProvider.GetRequiredService<PaidComponentRegistry>();
        var costs = scope.ServiceProvider.GetRequiredService<CostsAndLicensesQuery>();

        await registry.UpdateCostAsync(
            world.Admin, world.RegistryId, 1200m, "USD", null, true, world.AsOf);
        await registry.UpdateCostAsync(
            world.Admin, world.SecondRegistryId, 900m, "EUR", null, true, world.AsOf);

        var data = await costs.LoadAsync(world.ProjectId, world.AsOf);

        Assert.Equal(1200m, data.AnnualPerSeatByCurrency["USD"]);
        Assert.Equal(900m, data.AnnualPerSeatByCurrency["EUR"]);
        Assert.Equal(2, data.AnnualPerSeatByCurrency.Count);
    }

    [SkippableFact]
    public async Task A_cost_recorded_long_ago_is_flagged_stale()
    {
        Skip.IfNot(_fx.Available);

        // A renewal estimate built on a three-year-old figure is worse than no
        // estimate, because it looks like one.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var registry = scope.ServiceProvider.GetRequiredService<PaidComponentRegistry>();
        var costs = scope.ServiceProvider.GetRequiredService<CostsAndLicensesQuery>();

        await registry.UpdateCostAsync(
            world.Admin, world.RegistryId, 1200m, "USD", null, true, world.AsOf.AddYears(-3));

        var data = await costs.LoadAsync(world.ProjectId, world.AsOf);

        Assert.True(Assert.Single(data.Paid, p => p.Vendor == world.Vendor).Stale);
    }

    [SkippableFact]
    public async Task A_disabled_entry_stops_matching()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var registry = scope.ServiceProvider.GetRequiredService<PaidComponentRegistry>();
        var costs = scope.ServiceProvider.GetRequiredService<CostsAndLicensesQuery>();

        await registry.UpdateCostAsync(
            world.Admin, world.RegistryId, 1200m, "USD", null, enabled: false, world.AsOf);

        var data = await costs.LoadAsync(world.ProjectId, world.AsOf);

        Assert.DoesNotContain(data.Paid, p => p.Vendor == world.Vendor);
    }

    [SkippableFact]
    public async Task A_package_in_two_components_is_one_licence_obligation()
    {
        Skip.IfNot(_fx.Available);

        // Counting it twice would make a single AGPL dependency look like an
        // epidemic, and the screen's job is to make the real one findable.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var costs = scope.ServiceProvider.GetRequiredService<CostsAndLicensesQuery>();

        var data = await costs.LoadAsync(world.ProjectId, world.AsOf);

        Assert.Single(data.Obligations, o => o.Purl == world.SharedAgplPurl);
    }

    [SkippableFact]
    public async Task Denied_licences_sort_above_unknown_ones()
    {
        Skip.IfNot(_fx.Available);

        // Unknown is usually the longest list, and burying the denied rows
        // under it is how a denied row goes unread.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var costs = scope.ServiceProvider.GetRequiredService<CostsAndLicensesQuery>();

        var data = await costs.LoadAsync(world.ProjectId, world.AsOf);

        Assert.Equal(LicensePolicy.Tier.Denied, data.Obligations[0].Tier);
    }

    [SkippableFact]
    public async Task A_package_with_no_declared_licence_is_an_obligation_not_a_pass()
    {
        Skip.IfNot(_fx.Available);

        // A blank licence field is "nobody looked", not "permissive". Same rule
        // as a gate with no scan.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var costs = scope.ServiceProvider.GetRequiredService<CostsAndLicensesQuery>();

        var data = await costs.LoadAsync(world.ProjectId, world.AsOf);

        Assert.Contains(data.Obligations,
            o => o.Purl == world.UnlicensedPurl && o.Tier == LicensePolicy.Tier.Unknown);
    }

    [SkippableFact]
    public async Task Permissive_packages_are_tallied_but_not_listed()
    {
        Skip.IfNot(_fx.Available);

        // The list has a job: say what places a condition on shipping. The
        // majority that does not belongs in a count, not in rows.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var costs = scope.ServiceProvider.GetRequiredService<CostsAndLicensesQuery>();

        var data = await costs.LoadAsync(world.ProjectId, world.AsOf);

        Assert.True(data.LicenceTiers[LicensePolicy.Tier.Permissive] > 0);
        Assert.DoesNotContain(data.Obligations, o => o.Tier == LicensePolicy.Tier.Permissive);
    }

    [SkippableFact]
    public async Task A_project_with_no_sbom_reports_nothing_rather_than_all_clear()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var costs = scope.ServiceProvider.GetRequiredService<CostsAndLicensesQuery>();

        var data = await costs.LoadAsync(world.EmptyProjectId, world.AsOf);

        // Zero packages, which the screen renders as "nobody has looked" rather
        // than as a clean bill.
        Assert.Equal(0, data.DistinctPackages);
        Assert.Empty(data.Paid);
    }

    // ---- The registry --------------------------------------------------------

    [SkippableFact]
    public async Task An_over_broad_prefix_is_refused()
    {
        Skip.IfNot(_fx.Available);

        // A one-character prefix matches most of an SBOM, and this screen
        // reports what it matches as a cost.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var registry = scope.ServiceProvider.GetRequiredService<PaidComponentRegistry>();

        var result = await registry.AddAsync(world.Admin, "Acme", "Widgets", "A", "nuget");

        Assert.False(result.Success);
        Assert.False(result.WasDenied);
    }

    [SkippableFact]
    public async Task A_built_in_entry_cannot_be_deleted()
    {
        Skip.IfNot(_fx.Available);

        // Deleting it would only bring it back on the next upgrade, with the
        // operator's recorded cost gone.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var registry = scope.ServiceProvider.GetRequiredService<PaidComponentRegistry>();

        var result = await registry.RemoveAsync(world.Admin, world.BuiltInId);

        Assert.False(result.Success);
        Assert.Contains("Disable", result.Error!, StringComparison.OrdinalIgnoreCase);
    }

    [SkippableFact]
    public async Task Re_seeding_does_not_overwrite_a_recorded_cost()
    {
        Skip.IfNot(_fx.Available);

        // An upgrade adds vendors. It must not undo what somebody entered about
        // their own contract.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var registry = scope.ServiceProvider.GetRequiredService<PaidComponentRegistry>();
        var db = _fx.Db(scope);

        await registry.UpdateCostAsync(
            world.Admin, world.BuiltInId, 4321m, "GBP", null, true, world.AsOf);

        await PaidComponentRegistry.SeedAsync(db);

        var after = (await registry.ListAsync(world.AsOf)).Single(p => p.Id == world.BuiltInId);
        Assert.Equal(4321m, after.AnnualCostPerSeat);
        Assert.Equal("GBP", after.Currency);
    }

    [SkippableFact]
    public async Task Re_saving_an_unchanged_cost_does_not_refresh_its_date()
    {
        Skip.IfNot(_fx.Available);

        // Otherwise opening and saving the dialog launders a three-year-old
        // figure into a fresh one, and the staleness flag becomes decoration.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var registry = scope.ServiceProvider.GetRequiredService<PaidComponentRegistry>();

        var recorded = world.AsOf.AddYears(-2);
        await registry.UpdateCostAsync(world.Admin, world.BuiltInId, 500m, "USD", null, true, recorded);
        await registry.UpdateCostAsync(world.Admin, world.BuiltInId, 500m, "USD", null, true, world.AsOf);

        var after = (await registry.ListAsync(world.AsOf)).Single(p => p.Id == world.BuiltInId);

        Assert.Equal(recorded.Date, after.CostAsOf!.Value.Date);
        Assert.True(after.Stale);
    }

    [SkippableFact]
    public async Task A_lead_dev_cannot_set_a_cost()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var registry = scope.ServiceProvider.GetRequiredService<PaidComponentRegistry>();

        var result = await registry.UpdateCostAsync(
            world.LeadDev, world.RegistryId, 999m, "USD", null, true, world.AsOf);

        Assert.True(result.WasDenied);
    }

    // ---- Policy-driven rules (TFND-10 / F9.3) --------------------------------

    [SkippableFact]
    public async Task With_no_approval_required_every_paid_product_reads_as_approved()
    {
        Skip.IfNot(_fx.Available);

        // Approved is true when the policy does not ask the question, so a
        // caller can read it without also checking ApprovalRequired.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var costs = scope.ServiceProvider.GetRequiredService<CostsAndLicensesQuery>();

        var data = await costs.LoadAsync(world.ProjectId, world.AsOf);

        Assert.All(data.Paid, p => Assert.True(p.Approved));
        Assert.Equal(0, data.UnapprovedProducts);
    }

    [SkippableFact]
    public async Task An_unapproved_vendor_is_a_violation_when_the_policy_asks()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        await SetPolicyAsync(world, paid: new PaidComponentRules { RequireApproval = true });

        using var scope = _fx.Scope();
        var costs = scope.ServiceProvider.GetRequiredService<CostsAndLicensesQuery>();

        var data = await costs.LoadAsync(world.ProjectId, world.AsOf);

        Assert.True(data.UnapprovedProducts > 0);
        Assert.Contains(data.Paid, p => p.Vendor == world.Vendor && !p.Approved);
    }

    [SkippableFact]
    public async Task An_approved_vendor_is_not_a_violation()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        await SetPolicyAsync(world, paid: new PaidComponentRules
        {
            RequireApproval = true,
            // Cased differently on purpose: an approval typed by hand should
            // not fail on capitalisation.
            ApprovedVendors = [world.Vendor.ToUpperInvariant()],
        });

        using var scope = _fx.Scope();
        var costs = scope.ServiceProvider.GetRequiredService<CostsAndLicensesQuery>();

        var data = await costs.LoadAsync(world.ProjectId, world.AsOf);

        Assert.True(Assert.Single(data.Paid, p => p.Vendor == world.Vendor).Approved);
    }

    [SkippableFact]
    public async Task Unapproved_products_sort_above_expensive_ones()
    {
        Skip.IfNot(_fx.Available);

        // A policy violation outranks how much anything costs.
        var world = await SeedAsync();
        await SetPolicyAsync(world, paid: new PaidComponentRules
        {
            RequireApproval = true,
            ApprovedVendors = [world.Vendor],
        });

        using var scope = _fx.Scope();
        var registry = scope.ServiceProvider.GetRequiredService<PaidComponentRegistry>();
        var costs = scope.ServiceProvider.GetRequiredService<CostsAndLicensesQuery>();

        // The approved vendor is the expensive one; the unapproved one is free.
        await registry.UpdateCostAsync(world.Admin, world.RegistryId, 9999m, "USD", null, true, world.AsOf);

        var data = await costs.LoadAsync(world.ProjectId, world.AsOf);

        Assert.False(data.Paid[0].Approved);
    }

    [SkippableFact]
    public async Task A_policy_denylist_reclassifies_a_permissive_licence()
    {
        Skip.IfNot(_fx.Available);

        // The screen and the score have to agree, and both now read the policy.
        var world = await SeedAsync();
        await SetPolicyAsync(world, licenses: new LicenseRules { Deny = ["MIT"] });

        using var scope = _fx.Scope();
        var costs = scope.ServiceProvider.GetRequiredService<CostsAndLicensesQuery>();

        var data = await costs.LoadAsync(world.ProjectId, world.AsOf);

        Assert.Contains(data.Obligations,
            o => o.License == "MIT" && o.Tier == LicensePolicy.Tier.Denied);
    }

    [SkippableFact]
    public async Task A_policy_allowlist_clears_a_licence_the_table_denies()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        await SetPolicyAsync(world, licenses: new LicenseRules { Allow = ["AGPL-3.0"] });

        using var scope = _fx.Scope();
        var costs = scope.ServiceProvider.GetRequiredService<CostsAndLicensesQuery>();

        var data = await costs.LoadAsync(world.ProjectId, world.AsOf);

        // Cleared to permissive, so it drops out of the obligations list
        // entirely — permissive licences are tallied, not listed.
        Assert.DoesNotContain(data.Obligations, o => o.Purl == world.SharedAgplPurl);
    }

    /// <summary>
    /// Point this world's project at a policy carrying these rules.
    /// </summary>
    private async Task SetPolicyAsync(
        World world, LicenseRules? licenses = null, PaidComponentRules? paid = null)
    {
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);

        var policy = new RiskPolicy
        {
            Name = $"cost-policy-{Guid.NewGuid():N}",
            Config = new RiskPolicyConfig
            {
                Licenses = licenses ?? new LicenseRules(),
                PaidComponents = paid ?? new PaidComponentRules(),
            },
        };
        db.RiskPolicies.Add(policy);

        var project = await db.Projects.SingleAsync(p => p.Id == world.ProjectId);
        project.RiskPolicyId = policy.Id;

        await db.SaveChangesAsync();
    }

    // ---- Seed ----------------------------------------------------------------

    private sealed record World(
        Guid ProjectId, Guid EmptyProjectId, Guid RegistryId, Guid SecondRegistryId, Guid BuiltInId,
        string Vendor, string SharedAgplPurl, string UnlicensedPurl,
        DateTimeOffset AsOf, Principal Admin, Principal LeadDev);

    private async Task<World> SeedAsync()
    {
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);

        var suffix = Guid.NewGuid().ToString("N")[..8];
        var vendor = $"Vendor-{suffix}";
        var prefix = $"Vendor{suffix}.";

        var client = new Client { Name = $"cost-client-{suffix}" };
        var project = new Project { ClientId = client.Id, Name = $"cost-project-{suffix}" };
        var empty = new Project { ClientId = client.Id, Name = $"cost-empty-{suffix}" };
        var api = new Component { ProjectId = project.Id, Name = "api" };
        var web = new Component { ProjectId = project.Id, Name = "web" };

        db.Clients.Add(client);
        db.Projects.AddRange(project, empty);
        db.Components.AddRange(api, web);

        var agpl = $"pkg:nuget/Shared.Agpl.{suffix}@1.0.0";
        var unlicensed = $"pkg:nuget/Mystery.{suffix}@1.0.0";

        // The same AGPL package in BOTH components — one obligation, not two.
        foreach (var component in new[] { api, web })
        {
            var version = new ComponentVersion
            {
                ComponentId = component.Id, VersionString = "1.0.0", CommitSha = suffix + "dddddd",
            };
            var snapshot = new SbomSnapshot
            {
                ComponentVersionId = version.Id, ToolName = "syft", SpecVersion = "1.5",
            };

            db.ComponentVersions.Add(version);
            db.SbomSnapshots.Add(snapshot);

            db.SbomComponents.AddRange(
                Package(snapshot.Id, agpl, $"Shared.Agpl.{suffix}", "AGPL-3.0"),
                Package(snapshot.Id, $"pkg:nuget/Permissive.{component.Name}.{suffix}@1.0.0",
                    $"Permissive.{component.Name}.{suffix}", "MIT"));

            if (component == api)
            {
                db.SbomComponents.AddRange(
                    Package(snapshot.Id, $"pkg:nuget/{prefix}Grid@7.0.0", $"{prefix}Grid", "Commercial"),
                    Package(snapshot.Id, $"pkg:nuget/{prefix}Charts@7.0.0", $"{prefix}Charts", "Commercial"),
                    Package(snapshot.Id, unlicensed, $"Mystery.{suffix}", null));
            }
        }

        // Two registry entries, so the mixed-currency case has something to
        // work with, plus one standing in for a built-in row.
        var first = new PaidComponent
        {
            Vendor = vendor, Product = "Suite", PackagePrefix = prefix, Ecosystem = "nuget",
        };
        var second = new PaidComponent
        {
            Vendor = $"{vendor}-Two", Product = "Reports",
            PackagePrefix = $"Shared.Agpl.{suffix}", Ecosystem = "nuget",
        };
        var builtIn = new PaidComponent
        {
            Vendor = $"{vendor}-BuiltIn", Product = "Studio",
            PackagePrefix = $"NotPresent{suffix}.", Ecosystem = "nuget", IsBuiltIn = true,
        };
        db.PaidComponents.AddRange(first, second, builtIn);

        var user = new User
        {
            Login = $"cost-{suffix}",
            DisplayName = "Cost Admin",
            Email = $"cost-{suffix}@example.test",
            IsApproved = true,
        };
        db.Users.Add(user);

        await db.SaveChangesAsync();

        return new World(
            project.Id, empty.Id, first.Id, second.Id, builtIn.Id,
            vendor, agpl, unlicensed, DateTimeOffset.UtcNow,
            Admin: Principal.For(user.Id, user.Login, isAdmin: true, []),
            LeadDev: Principal.For(user.Id, user.Login, isAdmin: false, [ProjectRole.LeadDev]));
    }

    private static SbomComponent Package(Guid snapshotId, string purl, string name, string? licence) => new()
    {
        SbomSnapshotId = snapshotId,
        Purl = purl,
        Name = name,
        Version = "1.0.0",
        License = licence,
    };
}
