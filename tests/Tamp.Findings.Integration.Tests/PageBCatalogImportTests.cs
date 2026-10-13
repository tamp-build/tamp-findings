using AngleSharp.Dom;
using Bunit;
using Microsoft.AspNetCore.Components.Forms;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Compliance;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Web.Components.Pages;
using Tamp.Findings.Web.Routing;
using Tamp.Findings.Web.Security;

namespace Tamp.Findings.Integration.Tests;

/// <summary>
/// The control-catalog import dialog, RENDERED and USED (TFND-180, v3 §6).
///
/// ApiBControlCatalogImportTests covers the HTTP route an air-gapped operator curls.
/// This covers the path an operator actually takes: open /system/frameworks, press
/// Import file…, choose a catalog, press Import. That handler picks the files up as
/// IBrowserFile rather than IFormFile, resolves the principal from the circuit rather
/// than from a cookie, and reloads the page's own state afterwards — none of which the
/// endpoint tests touch.
///
/// Every test restores the catalog that was current when it started, for the reason
/// spelled out on ApiBControlCatalogImportTests: an import retires the current catalog,
/// and the whole suite shares one database.
/// </summary>
[Collection(DatabaseCollection.Name)]
public class PageBCatalogImportTests : IDisposable
{
    private readonly DatabaseFixture _fx;
    private readonly BunitContext _ctx = new();

    public PageBCatalogImportTests(DatabaseFixture fx)
    {
        _fx = fx;
        if (!_fx.Available) return;

        _ctx.Services.AddFindingsDb(_fx.ConnectionString!);
        _ctx.Services.AddFindingsApplication();
        _ctx.Services.AddScoped<RouteScope>();
        _ctx.Services.AddScoped<CurrentUser>();
    }

    public void Dispose()
    {
        _ctx.Dispose();
        GC.SuppressFinalize(this);
    }

    private const string Catalog = """
    {"catalog":{"metadata":{"version":"8.8.8","oscal-version":"1.2.2"},"groups":[
      {"id":"au","title":"Audit and Accountability","controls":[
        {"id":"au-2","title":"Event Logging",
         "parts":[{"name":"statement","prose":"Identify [Assignment: organization-defined event types]."}]}
      ]}
    ]}}
    """;

    private const string LowProfile = """
    {"profile":{"imports":[{"href":"catalog.json","include-controls":[{"with-ids":["au-2"]}]}]}}
    """;

    private async Task SignInAsync(bool admin)
    {
        using var seed = _fx.Scope();
        var db = _fx.Db(seed);
        var s = Guid.NewGuid().ToString("N")[..8];

        var user = new User
        {
            Login = $"ci-{s}", DisplayName = "ci", Email = $"ci{s}@e.test",
            IsApproved = true, IsAdmin = admin,
        };
        db.Users.Add(user);
        await db.SaveChangesAsync();

        var auth = _ctx.AddAuthorization();
        auth.SetAuthorized(user.Login);
        auth.SetClaims(new System.Security.Claims.Claim(
            CurrentUser.TampUserIdClaim, user.Id.ToString()));
    }

    /// <summary>
    /// Render the page and wait for its own Loading… marker to clear. Waiting for
    /// something the test is about would pass instantly against a half-loaded page
    /// (the trap from TFND-260).
    /// </summary>
    private IRenderedComponent<Frameworks> RenderPage()
    {
        var page = _ctx.Render<Frameworks>();
        page.WaitForAssertion(
            () => Assert.DoesNotContain(">Loading…<", page.Markup, StringComparison.Ordinal),
            TimeSpan.FromSeconds(30));
        return page;
    }

    /// <summary>
    /// Match a button by its EXACT trimmed label. A substring match looks fine and is a
    /// trap here: "Import file…" contains "Import" and comes first in the document, so
    /// every click meant for the footer's Import button landed on the one that merely
    /// opens the dialog — and the assertions still passed, against the wrong control.
    /// </summary>
    private static IElement Button(IRenderedComponent<Frameworks> page, string text) =>
        page.FindAll("button").First(b => b.TextContent.Trim() == text);

    /// <summary>Open the dialog and put a catalog, and optionally a Low profile, in it.</summary>
    private static void Choose(IRenderedComponent<Frameworks> page, string catalog, string? lowProfile = null)
    {
        Button(page, "Import file…").Click();
        page.WaitForAssertion(
            () => Assert.Contains("becomes the new current catalog", page.Markup, StringComparison.Ordinal),
            TimeSpan.FromSeconds(10));

        // Order is the markup's: catalog, then Low, Moderate, High.
        var inputs = page.FindComponents<InputFile>();
        inputs[0].UploadFiles(InputFileContent.CreateFromText(catalog, "catalog.json"));
        if (lowProfile is not null)
            inputs[1].UploadFiles(InputFileContent.CreateFromText(lowProfile, "low.json"));
    }

    /// <summary>
    /// Run a body that imports, then put the database back: whatever was current is
    /// current again, and anything the body created is gone.
    /// </summary>
    private async Task RestoringCatalogAsync(Func<Task> body)
    {
        Guid? wasCurrent;
        HashSet<Guid> before;
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            wasCurrent = (await db.ControlCatalogs.FirstOrDefaultAsync(c => c.IsCurrent))?.Id;
            before = (await db.ControlCatalogs.Select(c => c.Id).ToListAsync()).ToHashSet();
        }

        try
        {
            await body();
        }
        finally
        {
            using var scope = _fx.Scope();
            var db = _fx.Db(scope);
            db.ControlCatalogs.RemoveRange(
                await db.ControlCatalogs.Where(c => !before.Contains(c.Id)).ToListAsync());
            await db.SaveChangesAsync();

            if (wasCurrent is { } id && await db.ControlCatalogs.FindAsync(id) is { } prior)
            {
                prior.IsCurrent = true;
                await db.SaveChangesAsync();
            }
        }
    }

    [SkippableFact]
    public async Task Choosing_a_catalog_and_pressing_import_replaces_the_catalog_and_reports_it()
    {
        Skip.IfNot(_fx.Available);
        await RestoringCatalogAsync(async () =>
        {
            await SignInAsync(admin: true);
            var page = RenderPage();

            Choose(page, Catalog, LowProfile);
            Button(page, "Import").Click();

            // The dialog reports what came in, which is the point of doing this in the
            // product rather than over curl.
            page.WaitForAssertion(
                () => Assert.Contains("imported.", page.Markup, StringComparison.Ordinal),
                TimeSpan.FromSeconds(30));
            Assert.Contains("8.8.8", page.Markup, StringComparison.Ordinal);

            using var scope = _fx.Scope();
            var current = await _fx.Db(scope).ControlCatalogs.SingleAsync(c => c.IsCurrent);
            Assert.Equal("8.8.8", current.Version);

            // The profile was carried too — one control in Low, read from the profile
            // rather than guessed. The controls travel inline on the catalog as jsonb.
            Assert.Equal(1, current.Controls.Count(c => c.Baselines.HasFlag(BaselineLevel.Low)));
        });
    }

    [SkippableFact]
    public async Task Importing_the_same_file_twice_says_nothing_changed()
    {
        Skip.IfNot(_fx.Available);
        await RestoringCatalogAsync(async () =>
        {
            await SignInAsync(admin: true);
            var page = RenderPage();

            Choose(page, Catalog);
            Button(page, "Import").Click();
            page.WaitForAssertion(
                () => Assert.Contains("imported.", page.Markup, StringComparison.Ordinal),
                TimeSpan.FromSeconds(30));

            Button(page, "Import").Click();
            page.WaitForAssertion(
                () => Assert.Contains("Nothing changed", page.Markup, StringComparison.Ordinal),
                TimeSpan.FromSeconds(30));
        });
    }

    [SkippableFact]
    public async Task A_refused_file_is_reported_in_the_dialog_and_leaves_the_catalog_alone()
    {
        Skip.IfNot(_fx.Available);
        await RestoringCatalogAsync(async () =>
        {
            await SignInAsync(admin: true);

            Guid priorId;
            using (var scope = _fx.Scope())
                priorId = (await _fx.Db(scope).ControlCatalogs.SingleAsync(c => c.IsCurrent)).Id;

            var page = RenderPage();
            Choose(page, "this is not an OSCAL catalog");
            Button(page, "Import").Click();

            // The service's own wording, not just the word OSCAL — the dialog's standing
            // prose says "An OSCAL catalog (JSON) becomes the new current catalog", so a
            // looser assertion passes before anything is even uploaded.
            page.WaitForAssertion(
                () => Assert.Contains("does not read as an OSCAL catalog", page.Markup, StringComparison.Ordinal),
                TimeSpan.FromSeconds(30));
            Assert.DoesNotContain("imported.", page.Markup, StringComparison.Ordinal);

            using var after = _fx.Scope();
            Assert.Equal(priorId, (await _fx.Db(after).ControlCatalogs.SingleAsync(c => c.IsCurrent)).Id);
        });
    }

    [SkippableFact]
    public async Task Import_cannot_be_pressed_until_a_catalog_is_chosen()
    {
        Skip.IfNot(_fx.Available);
        await SignInAsync(admin: true);
        var page = RenderPage();

        Button(page, "Import file…").Click();
        page.WaitForAssertion(
            () => Assert.Contains("becomes the new current catalog", page.Markup, StringComparison.Ordinal),
            TimeSpan.FromSeconds(10));

        // A disabled control with a reason, per the house pattern — not a hidden one.
        Assert.True(Button(page, "Import").HasAttribute("disabled"));
        Assert.Contains("Choose a catalog file first", page.Markup, StringComparison.Ordinal);
    }

    [SkippableFact]
    public async Task A_non_admin_is_not_offered_the_import()
    {
        Skip.IfNot(_fx.Available);

        // Replacing the catalog replaces instance-wide reference content that every
        // project resolves against — the same authority as applying a policy pack.
        await SignInAsync(admin: false);
        var page = RenderPage();

        Assert.True(Button(page, "Import file…").HasAttribute("disabled"));
    }

    [SkippableFact]
    public async Task Check_for_update_stays_disabled_and_says_why()
    {
        Skip.IfNot(_fx.Available);
        await SignInAsync(admin: true);
        var page = RenderPage();

        // This instance is explicitly allowed to be air-gapped (v3 §6), so the button
        // has to name what it would need rather than promise a ticket.
        var check = Button(page, "Check for update");
        Assert.True(check.HasAttribute("disabled"));
        Assert.Contains("usnistgov/oscal-content", check.GetAttribute("title")!, StringComparison.Ordinal);
    }
}
