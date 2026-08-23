using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Api.Authentication;
using Tamp.Findings.Api.Contracts;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Integration.Tests;

// Which scope a suppression is AUTHORIZED at (TFND-132).
//
// The rule these assert is one sentence: the scope a suppression is authorized
// at must be derived from the fields the MATCHER actually uses, never from
// whatever fields happen to be on the request.
//
// Getting that wrong is not a cosmetic mismatch. `SuppressionMatcher` ignores
// ComponentId for RuleEverywhere, so a request that carries one to satisfy the
// authorization check produces a row that silences the rule for every client on
// the instance — an escalation from one component to the whole deployment,
// through a field the stored behaviour never reads.
[Collection(DatabaseCollection.Name)]
public class SuppressionScopeEscalationTests
{
    private readonly DatabaseFixture _fx;

    public SuppressionScopeEscalationTests(DatabaseFixture fx) => _fx = fx;

    [SkippableFact]
    public async Task RuleEverywhere_authorizes_at_the_instance_even_when_a_component_is_supplied()
    {
        Skip.IfNot(_fx.Available);

        // THE escalation. A Lead Dev on one component sends RuleEverywhere with
        // that component's id. If the target resolves to the component, their
        // role authorizes it — and the stored row then silences the rule for
        // every client, because the matcher never looks at ComponentId for this
        // scope.
        var world = await SeedAsync();

        var target = await TargetForAsync(world, new SuppressionCreateRequest(
            SuppressionScope.RuleEverywhere,
            FindingId: null,
            RuleId: "CA1822",
            ComponentId: world.ComponentId,
            FilePath: null,
            Reason: "escalation attempt",
            ExpiresAt: null));

        Assert.Equal(ScopeTarget.Instance, target);
        Assert.Null(target.ComponentId);
    }

    [SkippableFact]
    public async Task RuleOnFile_authorizes_at_the_instance_even_when_a_finding_is_supplied()
    {
        Skip.IfNot(_fx.Available);

        // Same shape through the other unanchored scope. RuleOnFile matches on
        // rule id and path with no tenant in the predicate, so a finding id
        // supplied alongside it buys authorization it does not constrain.
        var world = await SeedAsync();

        var target = await TargetForAsync(world, new SuppressionCreateRequest(
            SuppressionScope.RuleOnFile,
            FindingId: world.FindingId,
            RuleId: "CA1822",
            ComponentId: null,
            FilePath: "src/Api/Program.cs",
            Reason: "escalation attempt",
            ExpiresAt: null));

        Assert.Equal(ScopeTarget.Instance, target);
    }

    [SkippableFact]
    public async Task RuleOnComponent_still_authorizes_at_that_component()
    {
        Skip.IfNot(_fx.Available);

        // The scopes the matcher DOES anchor must keep resolving to their
        // anchor — otherwise the fix for the escalation would quietly demand
        // instance Admin for every ordinary suppression, which is a different
        // way to break the feature.
        var world = await SeedAsync();

        var target = await TargetForAsync(world, new SuppressionCreateRequest(
            SuppressionScope.RuleOnComponent,
            FindingId: null,
            RuleId: "CA1822",
            ComponentId: world.ComponentId,
            FilePath: null,
            Reason: "noisy here",
            ExpiresAt: null));

        Assert.Equal(world.ComponentId, target.ComponentId);
        Assert.Equal(world.ProjectId, target.ProjectId);
    }

    [SkippableFact]
    public async Task SingleFinding_still_authorizes_at_the_findings_own_component()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();

        var target = await TargetForAsync(world, new SuppressionCreateRequest(
            SuppressionScope.SingleFinding,
            FindingId: world.FindingId,
            RuleId: null,
            ComponentId: null,
            FilePath: null,
            Reason: "reviewed",
            ExpiresAt: null));

        Assert.Equal(world.ComponentId, target.ComponentId);
    }

    [SkippableFact]
    public async Task A_supplied_component_cannot_narrow_a_single_finding_away_from_its_own()
    {
        Skip.IfNot(_fx.Available);

        // A finding-scoped suppression is anchored by the FINDING. A component
        // id sent alongside it must not be what the check runs against, or the
        // same trick works one tier down: authorize on a component you hold,
        // suppress a finding on one you do not.
        var world = await SeedAsync();

        var target = await TargetForAsync(world, new SuppressionCreateRequest(
            SuppressionScope.SingleFinding,
            FindingId: world.FindingId,
            RuleId: null,
            ComponentId: world.OtherComponentId,
            FilePath: null,
            Reason: "escalation attempt",
            ExpiresAt: null));

        Assert.Equal(world.ComponentId, target.ComponentId);
        Assert.NotEqual(world.OtherComponentId, target.ComponentId);
    }

    // ---- Helpers -------------------------------------------------------------

    private async Task<ScopeTarget> TargetForAsync(World world, SuppressionCreateRequest request)
    {
        using var scope = _fx.Scope();

        var http = new DefaultHttpContext
        {
            RequestServices = scope.ServiceProvider,
            User = new ClaimsPrincipal(new ClaimsIdentity(
                [new Claim(AuthExtensions.TampUserIdClaim, world.UserId.ToString())], "Test")),
        };

        var acting = await SuppressionAuthorization.ResolveActorAsync(
            http,
            scope.ServiceProvider.GetRequiredService<PrincipalResolver>(),
            _fx.Db(scope),
            request,
            CancellationToken.None);

        return acting.Target;
    }

    private sealed record World(
        Guid UserId, Guid ClientId, Guid ProjectId, Guid ComponentId, Guid OtherComponentId,
        Guid FindingId);

    private async Task<World> SeedAsync()
    {
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);

        var suffix = Guid.NewGuid().ToString("N")[..8];

        var client = new Client { Name = $"esc-client-{suffix}" };
        var project = new Project { ClientId = client.Id, Name = $"esc-project-{suffix}" };
        var component = new Component { ProjectId = project.Id, Name = "api" };
        var other = new Component { ProjectId = project.Id, Name = "web" };
        var version = new ComponentVersion
        {
            ComponentId = component.Id, VersionString = "1.0.0", CommitSha = suffix + "cccccc",
        };

        var finding = new Finding
        {
            ComponentVersionId = version.Id,
            Hash = $"esc-{suffix}",
            Scanner = ScannerKind.Roslyn,
            RuleId = "CA1822",
            Severity = Severity.Low,
            Title = "Mark members as static",
            FilePath = "src/Api/Program.cs",
            Line = 3,
        };

        var user = new User
        {
            Login = $"esc-{suffix}",
            DisplayName = "Escalation Tester",
            Email = $"esc-{suffix}@example.test",
            IsApproved = true,
        };

        db.Clients.Add(client);
        db.Projects.Add(project);
        db.Components.AddRange(component, other);
        db.ComponentVersions.Add(version);
        db.Findings.Add(finding);
        db.Users.Add(user);

        // Lead Dev on ONE component. Nothing at the client, nothing at the
        // instance — which is exactly the position the escalation starts from.
        db.ProjectRoleAssignments.Add(new ProjectRoleAssignment
        {
            UserId = user.Id,
            ClientId = client.Id,
            ProjectId = project.Id,
            ComponentId = component.Id,
            Role = ProjectRole.LeadDev,
        });

        await db.SaveChangesAsync();

        return new World(user.Id, client.Id, project.Id, component.Id, other.Id, finding.Id);
    }
}
