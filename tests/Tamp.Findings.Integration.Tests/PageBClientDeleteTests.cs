using Bunit;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;
using Tamp.Findings.Web.Components.Pages;
using Tamp.Findings.Web.Routing;
using Tamp.Findings.Web.Security;

namespace Tamp.Findings.Integration.Tests;

/// <summary>
/// The client page's delete affordance, RENDERED (TFND-169).
///
/// The endpoint has its own tests; these cover the three UI branches that the HTTP
/// tests cannot see, and that nothing would have looked at before bUnit existed
/// (TFND-260) — which is how the TFND-257 wall shipped.
/// </summary>
[Collection(DatabaseCollection.Name)]
public class PageBClientDeleteTests : IDisposable
{
    private readonly DatabaseFixture _fx;
    private readonly BunitContext _ctx = new();

    public PageBClientDeleteTests(DatabaseFixture fx)
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

    private async Task<string> SignInWithAClientAsync(bool admin)
    {
        using var seed = _fx.Scope();
        var db = _fx.Db(seed);
        var s = Guid.NewGuid().ToString("N")[..8];

        var user = new User
        {
            Login = $"cd-{s}", DisplayName = admin ? "An Admin" : "A Viewer",
            Email = $"cd{s}@e.test", IsApproved = true, IsAdmin = admin,
        };
        var client = new Client { Name = $"cd-client-{s}" };
        db.Users.Add(user);
        db.Clients.Add(client);

        // A non-admin needs a grant, or the page resolves no visible client and renders
        // nothing at all — which would make the "does not offer delete" assertion pass
        // for entirely the wrong reason.
        if (!admin)
        {
            db.ProjectRoleAssignments.Add(new ProjectRoleAssignment
            {
                UserId = user.Id, Role = ProjectRole.Architect, ClientId = client.Id, ProjectId = null,
            });
        }

        await db.SaveChangesAsync();

        var auth = _ctx.AddAuthorization();
        auth.SetAuthorized(user.Login);
        auth.SetClaims(new System.Security.Claims.Claim(
            CurrentUser.TampUserIdClaim, user.Id.ToString()));

        return client.Name;
    }

    private IRenderedComponent<ClientPage> RenderFor(string clientName)
    {
        var page = _ctx.Render<ClientPage>(p => p.Add(c => c.Client, clientName));

        // Wait for the not-found branch to GO, not for the client's name to appear.
        //
        // The name is no use as a settle signal: _detail is null until the async load
        // finishes, so the first render is the not-found card — and that card quotes the
        // name back ("No client matches cd-client-…"). Waiting for the name therefore
        // passes instantly against the error page, and the assertion that follows reads
        // markup for a client the page has not loaded yet. Found the hard way.
        page.WaitForAssertion(
            () => Assert.DoesNotContain("Client not found", page.Markup, StringComparison.Ordinal),
            TimeSpan.FromSeconds(10));
        return page;
    }

    [SkippableFact]
    public async Task An_admin_is_offered_the_delete()
    {
        Skip.IfNot(_fx.Available);
        var name = await SignInWithAClientAsync(admin: true);

        var page = RenderFor(name);

        Assert.Contains("Delete this client", page.Markup, StringComparison.Ordinal);
    }

    [SkippableFact]
    public async Task An_architect_on_the_client_cannot_use_it()
    {
        Skip.IfNot(_fx.Available);

        // The page's other admin-ish gate (_canEdit) uses Capability.CreateProject, which
        // an Architect holds. Reusing it for delete would let whoever may add a project to
        // this client destroy the client and every project in it, so this asserts the two
        // gates really are different.
        //
        // The card is still SHOWN, disabled, with the reason — the house pattern
        // everywhere else on this page, and the one the Result type describes: a denial is
        // a disabled control with a reason, not a thing that silently is not there. So the
        // property under test is that the control cannot be used, not that it is absent.
        var name = await SignInWithAClientAsync(admin: false);

        var page = RenderFor(name);

        var delete = page.FindAll("button")
            .First(b => b.TextContent.Contains("Delete client", StringComparison.Ordinal));

        Assert.True(delete.HasAttribute("disabled"));
        Assert.Contains("administrator", page.Markup, StringComparison.OrdinalIgnoreCase);
    }

    [SkippableFact]
    public async Task The_confirm_button_stays_disabled_until_the_name_is_echoed_exactly()
    {
        Skip.IfNot(_fx.Available);
        var name = await SignInWithAClientAsync(admin: true);
        var page = RenderFor(name);

        page.FindAll("button")
            .First(b => b.TextContent.Contains("Delete client", StringComparison.Ordinal))
            .Click();

        // Opened, and refusing to arm itself.
        page.WaitForAssertion(
            () => Assert.Contains("to confirm", page.Markup, StringComparison.OrdinalIgnoreCase),
            TimeSpan.FromSeconds(10));

        var confirm = () => page.FindAll("button")
            .First(b => b.TextContent.Contains("Delete permanently", StringComparison.Ordinal));
        Assert.True(confirm().HasAttribute("disabled"));

        // Target THIS dialog's field by its label. The page carries several dialogs, each
        // with its own TextField, so "the first input in the document" belongs to the
        // client-settings dialog and dispatching to it throws.
        // TextField binds on oninput, not onchange — Change() throws MissingEventHandler.
        var echo = () => page.FindAll("label.field")
            .First(f => f.TextContent.Contains("to confirm", StringComparison.Ordinal))
            .QuerySelector("input")!;

        // A near-miss must not arm it either — the echo exists precisely so this cannot
        // be passed by accident.
        echo().Input(name.ToUpperInvariant());
        Assert.True(confirm().HasAttribute("disabled"));

        echo().Input(name);
        page.WaitForAssertion(
            () => Assert.False(confirm().HasAttribute("disabled")),
            TimeSpan.FromSeconds(10));

        // And nothing has been deleted by merely arming the button.
        using var scope = _fx.Scope();
        Assert.True(await _fx.Db(scope).Clients.AnyAsync(c => c.Name == name));
    }
}
