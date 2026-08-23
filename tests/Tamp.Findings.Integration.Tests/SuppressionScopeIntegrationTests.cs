using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Integration.Tests;

// Scope inheritance against a real database — TFND-19's positive acceptance
// criterion, which could not be asserted until now:
//
//   "An InfoSecOfficer assigned at the Client level can suppress for any
//    project/component beneath."
//
// The negative case (no assignment gets refused) was already covered without a
// database. The positive one needs real rows, because what is being tested is
// the query that loads assignments and the resolution applied to them — not
// the matrix, which is unit-tested.
[Collection(DatabaseCollection.Name)]
public class SuppressionScopeIntegrationTests
{
    private readonly DatabaseFixture _fx;

    public SuppressionScopeIntegrationTests(DatabaseFixture fx) => _fx = fx;

    [SkippableFact]
    public async Task A_client_level_infosec_officer_can_author_anywhere_beneath()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync(grantAt: Tier.Client, ProjectRole.InfoSecOfficer);
        using var scope = _fx.Scope();
        var resolver = scope.ServiceProvider.GetRequiredService<PrincipalResolver>();
        var capabilities = scope.ServiceProvider.GetRequiredService<CapabilityEvaluator>();

        foreach (var target in new[]
                 {
                     ScopeTarget.Client(world.ClientId),
                     ScopeTarget.Project(world.ClientId, world.ProjectId),
                     ScopeTarget.Component(world.ClientId, world.ProjectId, world.ComponentId),
                 })
        {
            var principal = await resolver.ResolveAsync(world.UserId, target);

            Assert.NotNull(principal);
            Assert.True(capabilities.Allows(principal!, Capability.AuthorSuppression),
                $"client-level grant should reach {target}");
        }
    }

    [SkippableFact]
    public async Task A_user_with_no_assignment_is_a_viewer_and_cannot_author()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync(grantAt: Tier.None, ProjectRole.InfoSecOfficer);
        using var scope = _fx.Scope();
        var resolver = scope.ServiceProvider.GetRequiredService<PrincipalResolver>();
        var capabilities = scope.ServiceProvider.GetRequiredService<CapabilityEvaluator>();

        var principal = await resolver.ResolveAsync(
            world.UserId, ScopeTarget.Component(world.ClientId, world.ProjectId, world.ComponentId));

        Assert.NotNull(principal);
        Assert.Contains(Actor.Viewer, principal!.Actors);
        Assert.False(capabilities.Allows(principal, Capability.AuthorSuppression));
    }

    [SkippableFact]
    public async Task A_narrow_grant_overrides_a_broader_one()
    {
        Skip.IfNot(_fx.Available);

        // The consequential rule from TFND-70, now proven end to end: an
        // organisation-wide InfoSec Officer who is made a Lead Dev on ONE
        // component is demoted there. This is the behaviour most likely to
        // surprise someone, so it is worth proving against real rows rather
        // than only in a unit test with hand-built objects.
        var world = await SeedAsync(grantAt: Tier.Client, ProjectRole.InfoSecOfficer);

        using (var seed = _fx.Scope())
        {
            var db = _fx.Db(seed);
            db.ProjectRoleAssignments.Add(new ProjectRoleAssignment
            {
                UserId = world.UserId,
                Role = ProjectRole.LeadDev,
                ComponentId = world.ComponentId,
            });
            await db.SaveChangesAsync();
        }

        using var scope = _fx.Scope();
        var resolver = scope.ServiceProvider.GetRequiredService<PrincipalResolver>();
        var capabilities = scope.ServiceProvider.GetRequiredService<CapabilityEvaluator>();

        var atProject = await resolver.ResolveAsync(world.UserId, ScopeTarget.Project(world.ClientId, world.ProjectId));
        var atComponent = await resolver.ResolveAsync(
            world.UserId, ScopeTarget.Component(world.ClientId, world.ProjectId, world.ComponentId));

        // Still InfoSec on the project, where nothing overrides.
        Assert.True(capabilities.Allows(atProject!, Capability.AcceptRisk));
        // Demoted on the component they were narrowed on.
        Assert.False(capabilities.Allows(atComponent!, Capability.AcceptRisk));
        Assert.True(capabilities.Allows(atComponent!, Capability.ManageIngestKey));
    }

    [SkippableFact]
    public async Task An_unapproved_user_resolves_to_nothing_rather_than_to_a_viewer()
    {
        Skip.IfNot(_fx.Available);

        // Falling through to Viewer would let anyone who has signed in once
        // read everything while awaiting approval.
        var world = await SeedAsync(grantAt: Tier.Client, ProjectRole.InfoSecOfficer, approved: false);
        using var scope = _fx.Scope();
        var resolver = scope.ServiceProvider.GetRequiredService<PrincipalResolver>();

        var principal = await resolver.ResolveAsync(world.UserId, ScopeTarget.Client(world.ClientId));

        Assert.Null(principal);
    }

    private enum Tier { None, Client, Project, Component }

    private sealed record World(Guid UserId, Guid ClientId, Guid ProjectId, Guid ComponentId);

    private async Task<World> SeedAsync(Tier grantAt, ProjectRole role, bool approved = true)
    {
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);

        var suffix = Guid.NewGuid().ToString("N")[..8];
        var user = new User { Login = $"user-{suffix}", DisplayName = $"user-{suffix}", IsApproved = approved };
        var client = new Client { Name = $"client-{suffix}" };
        var project = new Project { ClientId = client.Id, Name = $"project-{suffix}" };
        var component = new Component { ProjectId = project.Id, Name = $"component-{suffix}" };

        db.Users.Add(user);
        db.Clients.Add(client);
        db.Projects.Add(project);
        db.Components.Add(component);

        if (grantAt != Tier.None)
        {
            db.ProjectRoleAssignments.Add(new ProjectRoleAssignment
            {
                UserId = user.Id,
                Role = role,
                ClientId = grantAt == Tier.Client ? client.Id : null,
                ProjectId = grantAt == Tier.Project ? project.Id : null,
                ComponentId = grantAt == Tier.Component ? component.Id : null,
            });
        }

        await db.SaveChangesAsync();
        return new World(user.Id, client.Id, project.Id, component.Id);
    }
}
