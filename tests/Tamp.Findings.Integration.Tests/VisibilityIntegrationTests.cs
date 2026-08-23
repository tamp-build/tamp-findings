using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Projects;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Integration.Tests;

// The read-visibility boundary (TFND-133 / F2.3).
//
// Two clients on one instance, with something on the far side of every
// boundary, because that is the only shape in which a leak is detectable. The
// Client tier exists so one instance can hold several tenants, and cross-tenant
// read of security findings is the one thing that shape cannot tolerate.
[Collection(DatabaseCollection.Name)]
public class VisibilityIntegrationTests
{
    private readonly DatabaseFixture _fx;

    public VisibilityIntegrationTests(DatabaseFixture fx) => _fx = fx;

    // ---- Resolving the set ---------------------------------------------------

    [SkippableFact]
    public async Task An_admin_sees_everything()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var visibility = scope.ServiceProvider.GetRequiredService<VisibilityScope>();

        var visible = await visibility.ForAsync(world.AdminId);

        Assert.True(visible.Unrestricted);
    }

    [SkippableFact]
    public async Task An_unapproved_user_sees_nothing()
    {
        Skip.IfNot(_fx.Available);

        // Unapproved is "not yet a user of this instance", not "read-only" —
        // the same rule PrincipalResolver applies. The two have to agree, or
        // somebody awaiting approval reads everything through whichever forgot.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var visibility = scope.ServiceProvider.GetRequiredService<VisibilityScope>();

        var visible = await visibility.ForAsync(world.UnapprovedId);

        Assert.True(visible.IsEmpty);
        Assert.False(visible.Unrestricted);
    }

    [SkippableFact]
    public async Task A_user_who_does_not_exist_sees_nothing()
    {
        Skip.IfNot(_fx.Available);

        await SeedAsync();
        using var scope = _fx.Scope();
        var visibility = scope.ServiceProvider.GetRequiredService<VisibilityScope>();

        Assert.True((await visibility.ForAsync(Guid.NewGuid())).IsEmpty);
    }

    [SkippableFact]
    public async Task Nothing_is_never_the_same_as_everything()
    {
        Skip.IfNot(_fx.Available);

        // The whole defect in one assertion. Both have empty id sets; only one
        // is unrestricted. Inferring "unrestricted" from "no ids" would make
        // "granted nothing" mean "no limits".
        Assert.True(VisibleSet.Everything.Unrestricted);
        Assert.False(VisibleSet.Nothing.Unrestricted);
        Assert.False(VisibleSet.Everything.IsEmpty);
        Assert.True(VisibleSet.Nothing.IsEmpty);

        await Task.CompletedTask;
    }

    // ---- The boundary --------------------------------------------------------

    [SkippableFact]
    public async Task A_project_grant_does_not_reach_a_sibling_project()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var visibility = scope.ServiceProvider.GetRequiredService<VisibilityScope>();
        var hub = scope.ServiceProvider.GetRequiredService<ProjectHubQuery>();

        var visible = await visibility.ForAsync(world.ProjectUserId);

        Assert.NotNull(await hub.ResolveAsync(world.ClientName, world.ProjectName, visible));
        Assert.Null(await hub.ResolveAsync(world.ClientName, world.SiblingProjectName, visible));
    }

    [SkippableFact]
    public async Task No_grant_reaches_another_client()
    {
        Skip.IfNot(_fx.Available);

        // THE one that matters. A consultancy running this across engagements
        // is the stated shape of the Client tier.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var visibility = scope.ServiceProvider.GetRequiredService<VisibilityScope>();
        var hub = scope.ServiceProvider.GetRequiredService<ProjectHubQuery>();

        var visible = await visibility.ForAsync(world.ClientUserId);

        Assert.Null(await hub.ResolveAsync(world.OtherClientName, world.OtherProjectName, visible));
    }

    [SkippableFact]
    public async Task A_client_grant_reaches_every_project_under_it()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var visibility = scope.ServiceProvider.GetRequiredService<VisibilityScope>();
        var hub = scope.ServiceProvider.GetRequiredService<ProjectHubQuery>();

        var visible = await visibility.ForAsync(world.ClientUserId);

        Assert.NotNull(await hub.ResolveAsync(world.ClientName, world.ProjectName, visible));
        Assert.NotNull(await hub.ResolveAsync(world.ClientName, world.SiblingProjectName, visible));
    }

    [SkippableFact]
    public async Task A_component_grant_opens_its_project_as_a_container()
    {
        Skip.IfNot(_fx.Available);

        // Somebody granted a role on one component still has to be able to open
        // the project it lives in, or the tree has a hole in the middle of it.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var visibility = scope.ServiceProvider.GetRequiredService<VisibilityScope>();
        var hub = scope.ServiceProvider.GetRequiredService<ProjectHubQuery>();

        var visible = await visibility.ForAsync(world.ComponentUserId);

        Assert.NotNull(await hub.ResolveAsync(world.ClientName, world.ProjectName, visible));
        Assert.Null(await hub.ResolveAsync(world.ClientName, world.SiblingProjectName, visible));
    }

    // ---- The screens ---------------------------------------------------------

    [SkippableFact]
    public async Task The_portfolio_lists_only_what_the_reader_holds()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var visibility = scope.ServiceProvider.GetRequiredService<VisibilityScope>();
        var portfolio = scope.ServiceProvider.GetRequiredService<PortfolioQuery>();

        var rows = await portfolio.LoadAsync(await visibility.ForAsync(world.ProjectUserId));

        Assert.Contains(rows, r => r.ProjectName == world.ProjectName);
        Assert.DoesNotContain(rows, r => r.ProjectName == world.SiblingProjectName);
        Assert.DoesNotContain(rows, r => r.ProjectName == world.OtherProjectName);
    }

    [SkippableFact]
    public async Task The_portfolio_is_empty_for_a_reader_who_holds_nothing()
    {
        Skip.IfNot(_fx.Available);

        // Empty, not everything. On this database — which has projects from
        // every other test in the suite — the difference is very visible.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var visibility = scope.ServiceProvider.GetRequiredService<VisibilityScope>();
        var portfolio = scope.ServiceProvider.GetRequiredService<PortfolioQuery>();

        var rows = await portfolio.LoadAsync(await visibility.ForAsync(world.UnapprovedId));

        Assert.Empty(rows);
    }

    [SkippableFact]
    public async Task The_client_page_hides_projects_the_reader_does_not_hold()
    {
        Skip.IfNot(_fx.Available);

        // The client tile lists projects by name, which is a perfectly good
        // inventory of somebody else's estate if it is not filtered.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var visibility = scope.ServiceProvider.GetRequiredService<VisibilityScope>();
        var clients = scope.ServiceProvider.GetRequiredService<ClientQuery>();

        var detail = await clients.LoadAsync(world.ClientName, await visibility.ForAsync(world.ProjectUserId));

        Assert.NotNull(detail);
        Assert.Contains(detail!.Projects, p => p.Name == world.ProjectName);
        Assert.DoesNotContain(detail.Projects, p => p.Name == world.SiblingProjectName);
    }

    [SkippableFact]
    public async Task Another_clients_page_is_not_found_rather_than_forbidden()
    {
        Skip.IfNot(_fx.Available);

        // A 403 confirms the client exists, which tells one customer that
        // another is on this instance under that name.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var visibility = scope.ServiceProvider.GetRequiredService<VisibilityScope>();
        var clients = scope.ServiceProvider.GetRequiredService<ClientQuery>();

        var detail = await clients.LoadAsync(
            world.OtherClientName, await visibility.ForAsync(world.ClientUserId));

        Assert.Null(detail);
    }

    // ---- The bootstrap accommodation ----------------------------------------

    [SkippableFact]
    public async Task An_instance_with_assignments_is_segmented()
    {
        Skip.IfNot(_fx.Available);

        // The seed creates assignments, so from here on filtering is engaged
        // for everyone. The "no assignments anywhere" case cannot be exercised
        // against this shared database without deleting other tests' rows, and
        // deleting them to prove a point would be worse than not proving it —
        // so the unit of that rule is asserted here as the branch that runs.
        await SeedAsync();
        using var scope = _fx.Scope();
        var visibility = scope.ServiceProvider.GetRequiredService<VisibilityScope>();

        Assert.False(await visibility.UnsegmentedAsync());
    }

    [SkippableFact]
    public async Task A_user_with_no_assignments_sees_nothing_on_a_segmented_instance()
    {
        Skip.IfNot(_fx.Available);

        // The behaviour change this ticket is really about: before, an approved
        // user with no assignments was a Viewer everywhere.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var visibility = scope.ServiceProvider.GetRequiredService<VisibilityScope>();

        var visible = await visibility.ForAsync(world.UnassignedId);

        Assert.True(visible.IsEmpty);
    }

    // ---- Seed ----------------------------------------------------------------

    private sealed record World(
        Guid AdminId, Guid ClientUserId, Guid ProjectUserId, Guid ComponentUserId,
        Guid UnapprovedId, Guid UnassignedId,
        string ClientName, string ProjectName, string SiblingProjectName,
        string OtherClientName, string OtherProjectName);

    private async Task<World> SeedAsync()
    {
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);

        var suffix = Guid.NewGuid().ToString("N")[..8];

        var client = new Client { Name = $"vis-client-{suffix}" };
        var other = new Client { Name = $"vis-other-{suffix}" };

        var project = new Project { ClientId = client.Id, Name = $"vis-project-{suffix}" };
        var sibling = new Project { ClientId = client.Id, Name = $"vis-sibling-{suffix}" };
        var otherProject = new Project { ClientId = other.Id, Name = $"vis-foreign-{suffix}" };

        var component = new Component { ProjectId = project.Id, Name = "api" };

        db.Clients.AddRange(client, other);
        db.Projects.AddRange(project, sibling, otherProject);
        db.Components.Add(component);

        User Person(string name, bool approved = true, bool admin = false)
        {
            var user = new User
            {
                Login = $"vis-{name}-{suffix}",
                DisplayName = name,
                Email = $"vis-{name}-{suffix}@example.test",
                IsApproved = approved,
                IsAdmin = admin,
            };
            db.Users.Add(user);
            return user;
        }

        var admin = Person("admin", admin: true);
        var atClient = Person("client");
        var atProject = Person("project");
        var atComponent = Person("component");
        var unapproved = Person("unapproved", approved: false);
        var unassigned = Person("unassigned");

        db.ProjectRoleAssignments.AddRange(
            new ProjectRoleAssignment
            {
                UserId = atClient.Id, ClientId = client.Id, Role = ProjectRole.Auditor,
            },
            new ProjectRoleAssignment
            {
                UserId = atProject.Id, ClientId = client.Id, ProjectId = project.Id,
                Role = ProjectRole.LeadDev,
            },
            new ProjectRoleAssignment
            {
                UserId = atComponent.Id, ClientId = client.Id, ProjectId = project.Id,
                ComponentId = component.Id, Role = ProjectRole.Architect,
            });

        await db.SaveChangesAsync();

        return new World(
            admin.Id, atClient.Id, atProject.Id, atComponent.Id, unapproved.Id, unassigned.Id,
            client.Name, project.Name, sibling.Name, other.Name, otherProject.Name);
    }
}
