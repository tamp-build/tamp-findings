using Bunit;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Web.Components.Pages;
using Tamp.Findings.Web.Routing;
using Tamp.Findings.Web.Security;
using Tamp.Findings.Web.Services;

namespace Tamp.Findings.Integration.Tests;

/// <summary>
/// The Portfolio page's client-creation affordances, RENDERED (TFND-257).
///
/// Everything else in these suites exercises pages over HTTP, which runs their
/// initial render and nothing else — so a dialog, a conditional branch or a
/// button handler was reachable by no test at all. That is why the client
/// creation wall (TFND-257) shipped: the empty state had a disabled button and a
/// sentence, and nothing ever looked at it.
///
/// bUnit renders the component directly against the real services from the test
/// fixture, so these assert what an operator would actually see rather than what
/// the markup was meant to say.
/// </summary>
[Collection(DatabaseCollection.Name)]
public class PageBPortfolioClientDialogTests : IDisposable
{
    private readonly DatabaseFixture _fx;
    private readonly BunitContext _ctx = new();

    public PageBPortfolioClientDialogTests(DatabaseFixture fx)
    {
        _fx = fx;
        if (!_fx.Available) return;

        // bUnit gets its OWN container, built the way the host builds its own, rather
        // than borrowing service instances out of the fixture's scope.
        //
        // Borrowing was the thing that did not work. A service resolved from the
        // fixture closes over the fixture's FindingsDbContext, so registering that
        // same context here as a singleton left the rendered component sharing one
        // connection across two lifetimes — ObjectDisposedException inside Npgsql
        // mid-render, which is exactly the hazard behind "components must load data
        // in their own scope". Scoped registrations over the same connection string
        // give each resolution its own context and the problem goes away.
        //
        // These are the host's own registration calls (Program.cs), not a test-only
        // re-listing of what the pages need, so this cannot drift from how the app
        // actually wires up — and a page that starts needing another service fails
        // here the same way it would in production.
        _ctx.Services.AddFindingsDb(_fx.ConnectionString!);
        _ctx.Services.AddFindingsApplication();
        _ctx.Services.AddScoped<RouteScope>();

        // CurrentUser by TYPE, never as an instance: it takes an
        // AuthenticationStateProvider, and the fixture's belongs to a circuit that
        // does not exist here, so a pre-built one throws on first use. Constructing
        // it in bUnit's container hands it bUnit's provider — the one AddAuthorization
        // below drives.
        _ctx.Services.AddScoped<CurrentUser>();
    }

    public void Dispose()
    {
        _ctx.Dispose();
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Sign in as a user who is, or is not, an instance administrator. The page
    /// reads admin-ness through CurrentUser -> AuthenticationStateProvider, so
    /// the claim has to carry the real user id for the resolver to find the row.
    /// </summary>
    private async Task<User> SignInAsync(bool admin)
    {
        using var seed = _fx.Scope();
        var db = _fx.Db(seed);
        var user = new User
        {
            Login = $"page-b-{Guid.NewGuid():N}"[..18],
            DisplayName = admin ? "An Admin" : "A Viewer",
            IsApproved = true,
            IsAdmin = admin,
        };
        db.Users.Add(user);
        await db.SaveChangesAsync();

        var auth = _ctx.AddAuthorization();
        auth.SetAuthorized(user.Login);
        auth.SetClaims(new System.Security.Claims.Claim(
            CurrentUser.TampUserIdClaim, user.Id.ToString()));

        return user;
    }


    /// <summary>
    /// Render Portfolio and wait for its async initialisation to settle.
    ///
    /// Render() returns after the FIRST render, while OnInitializedAsync is still
    /// loading — so asserting straight away reads half-built markup, and tearing the
    /// context down straight away kills a query mid-flight ("connection is in state
    /// Connecting"). The page starts with _loading true and renders "Loading…", so
    /// that string clearing is the signal the data is in.
    ///
    /// Waiting on the absence of the loading marker rather than on the presence of
    /// whatever a test is about keeps this usable by the NEGATIVE tests too: waiting
    /// for "New client" to appear would pass the instant it rendered and tell the
    /// non-admin test nothing.
    /// </summary>
    private IRenderedComponent<Portfolio> RenderPortfolio()
    {
        var page = _ctx.Render<Portfolio>();
        page.WaitForAssertion(
            () => Assert.DoesNotContain("Loading…", page.Markup, StringComparison.Ordinal),
            TimeSpan.FromSeconds(10));
        return page;
    }

    [SkippableFact]
    public async Task An_admin_sees_a_New_client_action()
    {
        Skip.IfNot(_fx.Available);
        await SignInAsync(admin: true);

        var page = RenderPortfolio();

        Assert.Contains("New client", page.Markup, StringComparison.Ordinal);
    }

    [SkippableFact]
    public async Task A_non_admin_does_not_see_it()
    {
        Skip.IfNot(_fx.Available);

        // Creating a client needs Actor.Admin, so offering the button to anyone
        // else would be offering one that always fails.
        await SignInAsync(admin: false);

        var page = RenderPortfolio();

        Assert.DoesNotContain("New client", page.Markup, StringComparison.Ordinal);
    }

    [SkippableFact]
    public async Task The_New_client_dialog_opens_and_takes_a_name()
    {
        Skip.IfNot(_fx.Available);
        await SignInAsync(admin: true);

        var page = RenderPortfolio();
        page.FindAll("button")
            .First(b => b.TextContent.Contains("New client", StringComparison.Ordinal))
            .Click();

        // The dialog is open and it has somewhere to type — which is the whole of
        // what was missing before TFND-257: the empty state offered a DISABLED
        // button and a sentence, and no test ever looked at it.
        page.WaitForAssertion(
            () => Assert.NotEmpty(page.FindAll("input")),
            TimeSpan.FromSeconds(10));
    }
}
