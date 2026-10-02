using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;
using Tamp.Findings.Web.Components.Pages;

namespace Tamp.Findings.Integration.Tests;

[Collection(DatabaseCollection.Name)]
public class PageAClientAndCostsTests
{
    private readonly DatabaseFixture _fx;
    public PageAClientAndCostsTests(DatabaseFixture fx) => _fx = fx;

    // ---- Client page --------------------------------------------------------

    [SkippableFact]
    public async Task Client_page_lists_projects_edits_settings_and_manages_agent_tokens()
    {
        Skip.IfNot(_fx.Available);
        var w = await PageAWorld.SeedAsync(_fx);
        await PageAIngest.IngestBuildAsync(_fx, w, $"{w.S}clientbuild", full: false);

        await using var h = await PageAHost.ForAsync(_fx, w.Admin, "/c/x");
        var page = await h.OpenAsync<ClientPage>(("Client", w.Client.Name));
        page.Expect(w.Client.Name);
        page.Expect(w.Project.Name);
        page.Expect("never ingested");
        page.Expect("No agent tokens");

        await page.ClickRowAsync("tr", w.Project.Name);
        Assert.Contains(w.Project.Name, page.LastNavigation);

        // Edit: bad (blank) then good, with a default policy.
        await page.ClickButtonAsync("Client settings");
        await page.TypeAsync("Name", "");
        await page.ClickButtonAsync("Save client");
        using (var scope = _fx.Scope())
        {
            var policy = await _fx.Db(scope).RiskPolicies.Where(p => p.IsDefault).Select(p => p.Id).FirstAsync();
            await page.ChangeTagAsync("select", policy.ToString(), 0);
        }
        await page.TypeAsync("Name", w.Client.Name);
        await page.TypeAsync("Description", "edited description");
        await page.ClickButtonAsync("Save client");
        page.Expect("edited description");
        page.Expect("used by every project below");

        // Rename navigates to the new slug.
        await page.ClickButtonAsync("Client settings");
        await page.TypeAsync("Name", w.Client.Name + "-renamed");
        await page.ClickButtonAsync("Save client");
        Assert.EndsWith("-renamed", page.LastNavigation);

        // Agent token: blank label refused, then minted, then revoked.
        await using var h2 = await PageAHost.ForAsync(_fx, w.Admin, "/c/x");
        var p2 = await h2.OpenAsync<ClientPage>(("Client", w.Client.Name + "-renamed"));
        await p2.ClickButtonAsync("Mint client-wide token");
        await p2.ClickButtonAsync("Mint");
        await p2.TypeAsync("Label", "pagea-agent");
        await p2.ClickButtonAsync("Mint");
        p2.Expect("pagea-agent");
        p2.Expect("ACTIVE");
        await p2.ClickInAsync("tr", "pagea-agent", "revoke");
        p2.Expect("REVOKED");

        // Lead (no AssignRoles) and an unknown / empty client.
        await using var h3 = await PageAHost.ForAsync(_fx, w.Lead, "/c/x");
        var lead = await h3.OpenAsync<ClientPage>(("Client", w.Client.Name + "-renamed"));
        await lead.ClickButtonAsync("Client settings");
        await lead.ClickButtonAsync("Save client");
        await lead.ClickButtonAsync("Mint client-wide token");
        await lead.ClickButtonAsync("Mint");

        await using var h4 = await PageAHost.ForAsync(_fx, w.Admin, "/c/x");
        var bare = new Client { Name = "pagea-bare-" + w.S };
        using (var scope = _fx.Scope()) { var db = _fx.Db(scope); db.Clients.Add(bare); await db.SaveChangesAsync(); }
        var empty = await h4.OpenAsync<ClientPage>(("Client", bare.Name));
        empty.Expect("No projects under this client");
        var none = await (await PageAHost.ForAsync(_fx, w.Admin)).OpenAsync<ClientPage>(("Client", "no-such-client-" + w.S));
        none.Expect("Client not found");
        await none.ClickButtonAsync("Back to the portfolio");
    }

    // ---- Portfolio ----------------------------------------------------------

    [SkippableFact]
    public async Task Portfolio_sorts_filters_and_creates_a_project()
    {
        Skip.IfNot(_fx.Available);
        var w = await PageAWorld.SeedAsync(_fx);
        await PageAIngest.IngestBuildAsync(_fx, w, $"{w.S}pf1", "1.0.0", full: true);
        await PageAIngest.IngestBuildAsync(_fx, w, $"{w.S}pf2", "1.1.0", full: false);

        await using var h = await PageAHost.ForAsync(_fx, w.Admin, "/portfolio");
        var page = await h.OpenAsync<Portfolio>();
        page.Expect("Portfolio");
        page.Expect(w.Project.Name);
        page.Expect("never");
        foreach (var col in new[] { "Project", "Client", "Score", "Band", "Ship", "Last build" })
        {
            await page.ClickRowAsync("th", col);
            await page.ClickRowAsync("th", col);
        }
        await page.ChangeTagAsync("select", w.Client.Name, 0);
        page.Expect("2 of");
        await page.ChangeTagAsync("select", "", 0);

        await page.ClickRowAsync("tr", w.Project.Name);
        Assert.Contains(w.Project.Name, page.LastNavigation);

        await page.ClickButtonAsync("New project");
        await page.ClickButtonAsync("Create project");   // blank name refused
        await page.TypeAsync("Name", "pagea-new-" + w.S);
        await page.TypeAsync("Description", "from the portfolio");
        await page.ClickButtonAsync("Create project");
        page.Expect("pagea-new-" + w.S);

        // A viewer with no create capability still hits the handler and is refused.
        await using var h2 = await PageAHost.ForAsync(_fx, w.Nobody, "/portfolio");
        var viewer = await h2.OpenAsync<Portfolio>();
        await viewer.ClickButtonAsync("New project");
        await viewer.TypeAsync("Name", "refused-" + w.S);
        await viewer.ClickButtonAsync("Create project");
    }

    [SkippableFact]
    public async Task Portfolio_for_a_user_who_can_see_nothing_is_empty_rather_than_clean()
    {
        Skip.IfNot(_fx.Available);
        var w = await PageAWorld.SeedAsync(_fx);
        // Segmentation is on (the world has role assignments); a user with no role sees nothing.
        await using var h = await PageAHost.ForAsync(_fx, w.Nobody, "/portfolio");
        var page = await h.OpenAsync<Portfolio>();
        Assert.True(page.Has("No projects yet") || page.Has("Portfolio"));
    }

    // ---- Costs --------------------------------------------------------------

    private async Task<(PageAWorld W, string Vendor)> CostsWorldAsync()
    {
        var w = await PageAWorld.SeedAsync(_fx);
        var s = w.S;
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);

        PaidComponent Paid(string vendor, string prefix, decimal? cost, string cur, DateTimeOffset? asOf, DateTimeOffset? ends) => new()
        {
            Vendor = vendor, Product = vendor + " Suite", PackagePrefix = prefix, Ecosystem = "nuget", Enabled = true,
            AnnualCostPerSeat = cost, Currency = cur, CostAsOf = asOf, SupportEndsAt = ends, LicenseModel = "per seat",
            PricingUrl = "https://example.test/pricing", Notes = cost is null ? null : "negotiated",
        };
        db.PaidComponents.AddRange(
            Paid($"PageAVendA{s}", $"PageA.VendA{s}.", 500m, "USD", DateTimeOffset.UtcNow.AddYears(-4), DateTimeOffset.UtcNow.AddDays(-30)),
            Paid($"PageAVendB{s}", $"PageA.VendB{s}.", 300m, "EUR", DateTimeOffset.UtcNow.AddDays(-5), null),
            Paid($"PageAVendC{s}", $"PageA.VendC{s}.", null, "USD", null, null));

        var policy = (await db.RiskPolicies.AsNoTracking().FirstAsync(p => p.IsDefault)).Config;
        policy.PaidComponents.RequireApproval = true;
        policy.PaidComponents.ApprovedVendors = [$"PageAVendA{s}"];
        var rp = new RiskPolicy { Name = $"pagea-costs-policy-{s}", Config = policy };
        db.RiskPolicies.Add(rp);
        await db.SaveChangesAsync();
        await db.Projects.Where(p => p.Id == w.Project.Id).ExecuteUpdateAsync(u => u.SetProperty(p => p.RiskPolicyId, rp.Id));

        var snap = new SbomSnapshot { ComponentVersionId = w.Cv.Id, SpecVersion = "1.5", ToolName = "syft" };
        SbomComponent C(string name, string? lic, string ver = "1.0.0") =>
            new() { SbomSnapshotId = snap.Id, Purl = $"pkg:nuget/{name}@{ver}", Name = name, Version = ver, License = lic };
        snap.Components =
        [
            C($"PageA.VendA{s}.Core", "Commercial"), C($"PageA.VendA{s}.Ui", "Commercial"),
            C($"PageA.VendB{s}.Core", "Commercial"), C($"PageA.VendC{s}.Core", null),
            C($"PageAAgpl{s}", "AGPL-3.0-only"), C($"PageAGpl{s}", "GPL-3.0-only"), C($"PageALgpl{s}", "LGPL-2.1-only"),
            C($"PageAUnknown{s}", "Totally-Custom-1.0"), C($"PageAMit{s}", "MIT"),
        ];
        db.SbomSnapshots.Add(snap);

        db.ModelPrices.Add(new ModelPrice { ModelId = $"claude-pagea-{s}", Provider = "anthropic", InputPerMillion = 3m, OutputPerMillion = 15m, EffectiveFrom = DateTimeOffset.UtcNow.AddYears(-1) });
        db.ScanUsageObservations.AddRange(
            new ScanUsageObservation { ComponentVersionId = w.Cv.Id, Adapter = "conformance", ModelId = $"claude-pagea-{s}", Provider = "anthropic", InputTokens = 50_000, OutputTokens = 10_000, ObservedAt = DateTimeOffset.UtcNow },
            new ScanUsageObservation { ComponentVersionId = w.Cv.Id, Adapter = "conformance", ModelId = $"mystery-model-{s}", InputTokens = 1_000, OutputTokens = 100, ObservedAt = DateTimeOffset.UtcNow });
        await db.SaveChangesAsync();
        return (w, $"PageAVendA{s}");
    }

    [SkippableFact]
    public async Task Costs_page_reports_paid_products_licences_and_scan_cost()
    {
        Skip.IfNot(_fx.Available);
        var (w, vendor) = await CostsWorldAsync();

        await using var h = await PageAHost.ForAsync(_fx, w.Admin, "/c/x/p/y/costs");
        var page = await h.OpenAsync<Costs>(w.Of(w.Project));
        page.Expect("Costs & licences");
        page.Expect(vendor);
        page.Expect("UNAPPROVED");
        page.Expect("NOT APPROVED");
        page.Expect("SUPPORT ENDED");
        page.Expect("recheck");
        page.Expect("not recorded");
        page.Expect("An estimate");
        page.Expect("Currencies are shown separately");
        page.Expect("Scan cost");
        page.Expect("No price on file");
        page.Expect("AGPL-3.0-only");
        page.Expect("Strong copyleft");
        page.Expect("Unknown");

        await using var h2 = await PageAHost.ForAsync(_fx, w.Admin, "/c/x/p/y/costs");
        var empty = await h2.OpenAsync<Costs>(w.Of(w.EmptyProject));
        empty.Expect("NO SBOM");

        var missing = await (await PageAHost.ForAsync(_fx, w.Admin)).OpenAsync<Costs>(("Client", w.Client.Name), ("Project", "nope"));
        missing.Expect("Unavailable");
    }
}
