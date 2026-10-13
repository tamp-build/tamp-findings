using AngleSharp.Dom;
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
/// The project settings page's delete affordance, RENDERED (TFND-169).
///
/// The companion to PageBClientDeleteTests, and these go one step further: they
/// actually PERFORM the delete, so the handler that calls HierarchyService runs
/// rather than just the markup that offers it. Arming a button and pressing it are
/// different amounts of covered code, and only one of them is the thing an operator
/// does.
/// </summary>
[Collection(DatabaseCollection.Name)]
public class PageBProjectDeleteTests : IDisposable
{
    private readonly DatabaseFixture _fx;
    private readonly BunitContext _ctx = new();

    public PageBProjectDeleteTests(DatabaseFixture fx)
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

    private sealed record World(Guid ProjectId, string ClientName, string ProjectName);

    private async Task<World> SignInAsync(bool admin)
    {
        using var seed = _fx.Scope();
        var db = _fx.Db(seed);
        var s = Guid.NewGuid().ToString("N")[..8];

        var user = new User
        {
            Login = $"pd-{s}", DisplayName = "pd", Email = $"pd{s}@e.test",
            IsApproved = true, IsAdmin = admin,
        };
        var client = new Client { Name = $"pd-client-{s}" };
        var project = new Project { ClientId = client.Id, Name = $"pd-project-{s}" };
        var cv = new ComponentVersion { ProjectId = project.Id, VersionString = "1.0.0" };

        db.Users.Add(user);
        db.Clients.Add(client);
        db.Projects.Add(project);
        db.ComponentVersions.Add(cv);

        // A non-admin still needs to SEE the project, or the page renders "not found"
        // and the disabled-control assertion would pass for the wrong reason.
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

        return new World(project.Id, client.Name, project.Name);
    }

    /// <summary>
    /// Render the ACCOUNT tab, which is where the delete card lives, and wait for the
    /// not-found branch to go — not for the project's name, which the not-found card
    /// quotes back at you (the trap from TFND-260).
    /// </summary>
    private IRenderedComponent<ProjectSettings> RenderSettings(World w)
    {
        var page = _ctx.Render<ProjectSettings>(p => p
            .Add(c => c.Client, w.ClientName)
            .Add(c => c.Project, w.ProjectName)
            .Add(c => c.Tab, "account"));

        page.WaitForAssertion(
            () => Assert.DoesNotContain("Project not found", page.Markup, StringComparison.Ordinal),
            TimeSpan.FromSeconds(15));
        return page;
    }

    private static IElement Button(IRenderedComponent<ProjectSettings> page, string text) =>
        page.FindAll("button").First(b => b.TextContent.Contains(text, StringComparison.Ordinal));


    /// <summary>
    /// Poll the database until a condition holds. Needed because the thing under test
    /// finishes asynchronously after the click that started it, and no render event
    /// marks the moment the row is gone.
    /// </summary>
    private async Task WaitUntilAsync(Func<FindingsDbContext, Task<bool>> condition)
    {
        var deadline = DateTimeOffset.UtcNow.AddSeconds(10);
        while (true)
        {
            using (var scope = _fx.Scope())
            {
                if (await condition(_fx.Db(scope))) return;
            }
            if (DateTimeOffset.UtcNow > deadline) return;   // let the assertions report it
            await Task.Delay(100);
        }
    }

    [SkippableFact]
    public async Task An_admin_is_offered_the_delete()
    {
        Skip.IfNot(_fx.Available);
        var w = await SignInAsync(admin: true);

        var page = RenderSettings(w);

        Assert.Contains("Delete this project", page.Markup, StringComparison.Ordinal);
        Assert.False(Button(page, "Delete project").HasAttribute("disabled"));
    }

    [SkippableFact]
    public async Task An_architect_cannot_use_it()
    {
        Skip.IfNot(_fx.Available);

        // Capability.CreateProject -- which an Architect holds -- lets them create a
        // project. Deleting one destroys its whole evidence history, so it is Admin only.
        var w = await SignInAsync(admin: false);

        var page = RenderSettings(w);

        Assert.True(Button(page, "Delete project").HasAttribute("disabled"));
        Assert.Contains("administrator", page.Markup, StringComparison.OrdinalIgnoreCase);
    }

    [SkippableFact]
    public async Task Echoing_the_name_and_confirming_actually_deletes_it()
    {
        Skip.IfNot(_fx.Available);
        var w = await SignInAsync(admin: true);
        var page = RenderSettings(w);

        Button(page, "Delete project…").Click();
        page.WaitForAssertion(
            () => Assert.Contains("to confirm", page.Markup, StringComparison.OrdinalIgnoreCase),
            TimeSpan.FromSeconds(10));

        // Target this dialog's field by its label: the page carries several dialogs, each
        // with a TextField, and TextField binds on oninput rather than onchange.
        page.FindAll("label.field")
            .First(f => f.TextContent.Contains("to confirm", StringComparison.Ordinal))
            .QuerySelector("input")!
            .Input(w.ProjectName);

        Button(page, "Delete permanently").Click();

        // Click() returns once the handler hits its first await, so the delete is still
        // in flight. bUnit's WaitForAssertion re-runs on RENDER events, which is no use
        // for an assertion about the database — so wait on the database itself.
        await WaitUntilAsync(async db => !await db.Projects.AnyAsync(p => p.Id == w.ProjectId));

        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        Assert.False(await db.Projects.AnyAsync(p => p.Id == w.ProjectId));
        Assert.False(await db.ComponentVersions.AnyAsync(v => v.ProjectId == w.ProjectId));

        // And it is audited, with what it destroyed — the whole point of having an
        // in-product path instead of a psql session.
        var entry = await db.AuditEntries
            .SingleAsync(a => a.SubjectId == w.ProjectId && a.Action == "project.deleted");
        Assert.Contains("1 build(s)", entry.Detail!, StringComparison.Ordinal);
    }
}
