using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;
using Tamp.Findings.Web.Components.Pages;

namespace Tamp.Findings.Integration.Tests;

[Collection(DatabaseCollection.Name)]
public class PageASystemAdminTests
{
    private readonly DatabaseFixture _fx;
    public PageASystemAdminTests(DatabaseFixture fx) => _fx = fx;

    private async Task<(User Admin, User Pending, User Lead, Client Client)> SeedAsync()
    {
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var s = PageAHarness.Suffix();
        var admin = PageAHarness.NewUser(s, admin: true);
        var pending = PageAHarness.NewUser("p" + s, admin: false);
        pending.IsApproved = false;
        var lead = PageAHarness.NewUser("l" + s, admin: false);
        lead.LastLoginAt = DateTimeOffset.UtcNow;
        var client = new Client { Name = $"pagea-sa-{s}" };
        db.Users.AddRange(admin, pending, lead);
        db.Clients.Add(client);
        db.ProjectRoleAssignments.Add(new ProjectRoleAssignment
        {
            UserId = lead.Id, Role = ProjectRole.LeadDev, ClientId = client.Id, SodConflict = "also InfoSec here",
        });
        await db.SaveChangesAsync();
        return (admin, pending, lead, client);
    }

    [SkippableFact]
    public async Task Users_panel_renders_states_and_admin_actions_work()
    {
        Skip.IfNot(_fx.Available);
        var (admin, pending, lead, client) = await SeedAsync();
        await using var h = await PageAHost.ForAsync(_fx, admin, "/system/users");
        var page = await h.OpenAsync<SystemAdmin>(("Panel", "users"));

        page.Expect("Users & RBAC");
        page.Expect("PENDING");
        page.Expect("ADMIN");
        Assert.Contains(lead.Login, page.Text);

        await page.ClickInAsync("tr", pending.Login, "approve");
        await page.ClickInAsync("tr", pending.Login, "make admin");
        await page.ClickInAsync("tr", pending.Login, "remove admin");
        await page.ClickInAsync("tr", pending.Login, "suspend");

        await page.ClickRowAsync("tr", lead.Login);
        page.Expect("Role assignments");
        page.Expect("also InfoSec here");
        Assert.Contains(client.Name, page.Text);
        await page.ClickInAsync("table", "also InfoSec here", "revoke");
        page.Expect("No role assignments");
        await page.ClickRowAsync("tr", lead.Login); // deselect
    }

    [SkippableFact]
    public async Task Non_admin_sees_read_only_users_panel()
    {
        Skip.IfNot(_fx.Available);
        var (_, _, lead, _) = await SeedAsync();
        await using var h = await PageAHost.ForAsync(_fx, lead, "/system/users");
        var page = await h.OpenAsync<SystemAdmin>(("Panel", "users"));
        page.Expect("READ ONLY");

        // The disabled buttons still route through the handler and are refused by the service.
        await page.ClickRowAsync("tr", lead.Login);
    }

    [SkippableFact]
    public async Task Anonymous_viewer_gets_read_only_panels()
    {
        Skip.IfNot(_fx.Available);
        await using var h = await PageAHost.ForAsync(_fx, null, "/system/audit");
        var page = await h.OpenAsync<SystemAdmin>(("Panel", "audit"));
        page.Expect("READ ONLY");
    }

    [SkippableFact]
    public async Task Unknown_panel_offers_a_way_back()
    {
        Skip.IfNot(_fx.Available);
        var (admin, _, _, _) = await SeedAsync();
        await using var h = await PageAHost.ForAsync(_fx, admin, "/system/zzz");
        var page = await h.OpenAsync<SystemAdmin>(("Panel", "zzz"));
        page.Expect("Unknown panel");
        await page.ClickButtonAsync("Go to Users");
        Assert.EndsWith("/system/users", page.LastNavigation);
    }

    [SkippableFact]
    public async Task Authentication_panel_manages_providers_and_sign_in_policy()
    {
        Skip.IfNot(_fx.Available);
        var (admin, _, _, _) = await SeedAsync();
        await using var h = await PageAHost.ForAsync(_fx, admin, "/system/authentication");
        var page = await h.OpenAsync<SystemAdmin>(("Panel", "authentication"));
        page.Expect("Identity providers");

        // Add an OIDC provider.
        var scheme = "pa" + PageAHarness.Suffix();
        await page.ClickButtonAsync("Add provider");
        page.Expect("Add identity provider");
        await page.TypeAsync("Display name", "PageA IdP");
        await page.TypeAsync("Scheme", scheme);
        await page.TypeAsync("Authority", "https://login.example.test");
        await page.TypeAsync("Client id", "cid-" + scheme);
        await page.TypeAsync("Client secret", "s3cret");
        await page.TypeAsync("Extra scopes", "groups");
        await page.ClickButtonAsync("Save provider");
        page.Expect("PageA IdP");

        // Edit, flip kind (GitHub cannot assert MFA), then an invalid save shows an error.
        await page.ClickInAsync("tr", "PageA IdP", "edit");
        page.Expect("Edit identity provider");
        await page.ClickRowAsync("span", "GitHub OAuth");
        page.Expect("cannot assert MFA");
        await page.TypeAsync("Client id", "");
        await page.ClickButtonAsync("Save provider");
        await page.ClickButtonAsync("Cancel");

        // Sign-in policy.
        await page.TypeAsync("Allowed email domains", "@Example.Test other.test");
        await page.ClickRowAsync("span", "Admin");
        await page.ClickRowAsync("span", "Admin");
        await page.ClickButtonAsync("Save sign-in policy");
        page.Expect("Saved.");

        // Remove the provider via the confirm dialog.
        await page.ClickInAsync("tr", "PageA IdP", "remove");
        page.Expect("Remove identity provider");
        await page.ClickButtonAsync("Remove permanently");
    }

    [SkippableFact]
    public async Task Scanners_panel_toggles_and_saves_expected_scanners()
    {
        Skip.IfNot(_fx.Available);
        var (admin, _, _, _) = await SeedAsync();
        await using var h = await PageAHost.ForAsync(_fx, admin, "/system/scanners");
        var page = await h.OpenAsync<SystemAdmin>(("Panel", "scanners"));
        page.Expect("Scanners & ingest");

        await page.ChangeTagAsync("input", true, 0);
        await page.ClickButtonAsync("Save expectations");
        await page.ChangeTagAsync("input", false, 0);
        await page.ClickButtonAsync("Save expectations");
    }

    [SkippableFact]
    public async Task Paid_components_panel_edits_and_adds_vendors()
    {
        Skip.IfNot(_fx.Available);
        var (admin, _, _, _) = await SeedAsync();
        await using var h = await PageAHost.ForAsync(_fx, admin, "/system/paid-components");
        var page = await h.OpenAsync<SystemAdmin>(("Panel", "paid-components"));
        page.Expect("Costs ship blank on purpose");

        await page.ClickButtonAsync("edit");
        page.Expect("Record what this costs");
        await page.TypeAsync("Annual cost per developer seat", "abc");
        await page.ClickButtonAsync("Save");
        page.Expect("not a number");
        await page.TypeAsync("Annual cost per developer seat", "1200");
        await page.TypeAsync("Support ends", "nonsense");
        await page.ClickButtonAsync("Save");
        page.Expect("not a date");
        await page.TypeAsync("Support ends", "2030-01-01");
        await page.ClickButtonAsync("Save");

        var prefix = "PageA" + PageAHarness.Suffix() + ".";
        await page.ClickButtonAsync("Add a vendor");
        await page.ClickButtonAsync("Add"); // blank -> validation error
        await page.TypeAsync("Vendor", "PageA Vendor");
        await page.TypeAsync("Product", "Widgets");
        await page.TypeAsync("Package prefix", prefix);
        await page.TypeAsync("Ecosystem", "nuget");
        await page.ClickButtonAsync("Add");
        page.Expect("PageA Vendor");
    }

    [SkippableFact]
    public async Task Settings_panel_saves_and_audit_panel_filters()
    {
        Skip.IfNot(_fx.Available);
        var (admin, _, _, _) = await SeedAsync();
        await using var h = await PageAHost.ForAsync(_fx, admin, "/system/settings");
        var page = await h.OpenAsync<SystemAdmin>(("Panel", "settings"));
        page.Expect("Instance settings");

        await page.TypeAsync("Finding retention", "");
        await page.TypeAsync("Outbound SMTP host", "smtp.example.test");
        await page.TypeAsync("App id", "12345");
        await page.TypeAsync("Check name", "");
        await page.ClickButtonAsync("Save settings");
        page.Expect("Saved.");
        await page.TypeAsync("Outbound SMTP host", "");
        await page.TypeAsync("App id", "");
        await page.ClickButtonAsync("Save settings");

        await using var h2 = await PageAHost.ForAsync(_fx, admin, "/system/audit");
        var audit = await h2.OpenAsync<SystemAdmin>(("Panel", "audit"));
        audit.Expect("Audit log");
        foreach (var f in new[] { "risk", "access", "other", "all" })
            await audit.ClickRowAsync("span", f);
    }
}
