using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Approvals;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Integration.Tests;

// Pending approvals (TFND-116).
//
// The requirement is a GRAMMAR rather than three features: one representation
// used by POA&M, VEX and attestation alike, a pending item whose terminal
// action cannot be triggered twice, and an "awaiting you" that is driven by
// real assignment rather than by role.
[Collection(DatabaseCollection.Name)]
public class ApprovalIntegrationTests
{
    private readonly DatabaseFixture _fx;

    public ApprovalIntegrationTests(DatabaseFixture fx) => _fx = fx;

    [SkippableFact]
    public async Task A_request_makes_the_subject_read_as_pending()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var approvals = scope.ServiceProvider.GetRequiredService<ApprovalService>();

        await approvals.RequestAsync(
            world.LeadDev, world.Scope, ApprovalKind.PoamRiskAcceptance,
            "PoamItem", world.SubjectId, "The vendor has no patch.");

        var pending = await approvals.ForSubjectAsync("PoamItem", world.SubjectId);

        Assert.NotNull(pending);
        // Beside the terminal-status chip, never instead of it.
        Assert.Equal("pending risk acceptance", pending!.Qualifier);
    }

    [SkippableFact]
    public async Task One_kind_cannot_be_requested_twice_for_the_same_subject()
    {
        Skip.IfNot(_fx.Available);

        // Two live requests for one decision would let two people approve the
        // same thing.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var approvals = scope.ServiceProvider.GetRequiredService<ApprovalService>();

        await approvals.RequestAsync(
            world.LeadDev, world.Scope, ApprovalKind.PoamRiskAcceptance, "PoamItem", world.SubjectId);
        var again = await approvals.RequestAsync(
            world.LeadDev, world.Scope, ApprovalKind.PoamRiskAcceptance, "PoamItem", world.SubjectId);

        Assert.False(again.Success);
        Assert.False(again.WasDenied);
    }

    [SkippableFact]
    public async Task A_decision_cannot_be_taken_twice()
    {
        Skip.IfNot(_fx.Available);

        // TFND-116's acceptance criterion, and the reason a pending state is a
        // row rather than a computed flag.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var approvals = scope.ServiceProvider.GetRequiredService<ApprovalService>();

        var request = await approvals.RequestAsync(
            world.LeadDev, world.Scope, ApprovalKind.PoamRiskAcceptance, "PoamItem", world.SubjectId);

        Assert.True((await approvals.DecideAsync(world.InfoSec, request.Value, approve: true)).Success);
        var second = await approvals.DecideAsync(world.InfoSec, request.Value, approve: false);

        Assert.False(second.Success);
        Assert.Contains("already approved", second.Error!, StringComparison.OrdinalIgnoreCase);
    }

    [SkippableFact]
    public async Task Nobody_approves_their_own_request()
    {
        Skip.IfNot(_fx.Available);

        // The whole point of routing a risk acceptance through an approval is
        // that a second person looks at it.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var approvals = scope.ServiceProvider.GetRequiredService<ApprovalService>();

        var request = await approvals.RequestAsync(
            world.InfoSec, world.Scope, ApprovalKind.PoamRiskAcceptance, "PoamItem", world.SubjectId);

        var result = await approvals.DecideAsync(world.InfoSec, request.Value, approve: true);

        Assert.True(result.WasDenied);
    }

    [SkippableFact]
    public async Task An_admin_cannot_approve_a_risk_acceptance()
    {
        Skip.IfNot(_fx.Available);

        // AcceptRisk is an Authorizing Official decision that Admin
        // deliberately does not hold — and routing it through an approval must
        // not become a way around that.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var approvals = scope.ServiceProvider.GetRequiredService<ApprovalService>();

        var request = await approvals.RequestAsync(
            world.LeadDev, world.Scope, ApprovalKind.PoamRiskAcceptance, "PoamItem", world.SubjectId);

        var result = await approvals.DecideAsync(world.Admin, request.Value, approve: true);

        Assert.True(result.WasDenied);
    }

    [SkippableFact]
    public async Task A_named_assignee_is_a_real_assignment_not_a_hint()
    {
        Skip.IfNot(_fx.Available);

        // Somebody else holding the capability cannot quietly take it instead:
        // the record has to say who was asked and who answered.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var approvals = scope.ServiceProvider.GetRequiredService<ApprovalService>();

        var request = await approvals.RequestAsync(
            world.LeadDev, world.Scope, ApprovalKind.PoamRiskAcceptance,
            "PoamItem", world.SubjectId, assignedTo: world.OtherInfoSecUserId);

        var result = await approvals.DecideAsync(world.InfoSec, request.Value, approve: true);

        Assert.True(result.WasDenied);
        Assert.Contains("assigned to someone else", result.Error!, StringComparison.OrdinalIgnoreCase);
    }

    [SkippableFact]
    public async Task Awaiting_you_is_driven_by_capability_not_by_role_name()
    {
        Skip.IfNot(_fx.Available);

        // An unassigned request counts only for those who actually hold the
        // capability AT ITS SCOPE. A filter matching on role alone would put
        // every InfoSec officer's name on every decision.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var approvals = scope.ServiceProvider.GetRequiredService<ApprovalService>();

        await approvals.RequestAsync(
            world.LeadDev, world.Scope, ApprovalKind.PoamRiskAcceptance, "PoamItem", world.SubjectId);

        var forInfoSec = await approvals.AwaitingAsync(world.InfoSec, world.ResolveFor(world.InfoSec));
        var forLead = await approvals.AwaitingAsync(world.LeadDev, world.ResolveFor(world.LeadDev));

        Assert.Single(forInfoSec);
        // Not the Lead Dev's: they lack AcceptRisk, AND they asked for it.
        Assert.Empty(forLead);
    }

    [SkippableFact]
    public async Task Your_own_request_is_never_awaiting_you()
    {
        Skip.IfNot(_fx.Available);

        // You cannot decide it, so it is not waiting on you.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var approvals = scope.ServiceProvider.GetRequiredService<ApprovalService>();

        await approvals.RequestAsync(
            world.InfoSec, world.Scope, ApprovalKind.PoamRiskAcceptance, "PoamItem", world.SubjectId);

        var awaiting = await approvals.AwaitingAsync(world.InfoSec, world.ResolveFor(world.InfoSec));

        Assert.Empty(awaiting);
    }

    [SkippableFact]
    public async Task A_decided_approval_stops_being_pending()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var approvals = scope.ServiceProvider.GetRequiredService<ApprovalService>();

        var request = await approvals.RequestAsync(
            world.LeadDev, world.Scope, ApprovalKind.PoamRiskAcceptance, "PoamItem", world.SubjectId);
        await approvals.DecideAsync(world.InfoSec, request.Value, approve: true);

        Assert.Null(await approvals.ForSubjectAsync("PoamItem", world.SubjectId));
    }

    [SkippableFact]
    public async Task Withdrawing_is_not_a_rejection()
    {
        Skip.IfNot(_fx.Available);

        // Nobody said no.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var approvals = scope.ServiceProvider.GetRequiredService<ApprovalService>();
        var db = _fx.Db(scope);

        var request = await approvals.RequestAsync(
            world.LeadDev, world.Scope, ApprovalKind.PoamRiskAcceptance, "PoamItem", world.SubjectId);
        await approvals.CancelAsync(world.LeadDev, request.Value);

        var row = db.PendingApprovals.Single(a => a.Id == request.Value);

        Assert.Equal(ApprovalState.Cancelled, row.State);
        Assert.NotEqual(ApprovalState.Rejected, row.State);
    }

    [SkippableFact]
    public async Task Every_approval_step_is_audited_in_the_risk_class()
    {
        Skip.IfNot(_fx.Available);

        // "Approvals belong in the risk class" — TFND-116.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var approvals = scope.ServiceProvider.GetRequiredService<ApprovalService>();
        var db = _fx.Db(scope);

        var request = await approvals.RequestAsync(
            world.LeadDev, world.Scope, ApprovalKind.PoamRiskAcceptance, "PoamItem", world.SubjectId);
        await approvals.DecideAsync(world.InfoSec, request.Value, approve: true);

        var entries = db.AuditEntries.Where(a => a.SubjectId == world.SubjectId).ToArray();

        Assert.Equal(2, entries.Length);
        Assert.All(entries, e => Assert.Equal(AuditClass.Risk, e.Class));
    }

    [SkippableFact]
    public async Task The_grammar_is_the_same_for_vex_and_attestation()
    {
        Skip.IfNot(_fx.Available);

        // One representation, used by all three. Three separate pending flags
        // would have produced three slightly different answers to one question.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var approvals = scope.ServiceProvider.GetRequiredService<ApprovalService>();

        var vexSubject = Guid.NewGuid();
        var attestationSubject = Guid.NewGuid();

        await approvals.RequestAsync(
            world.LeadDev, world.Scope, ApprovalKind.VexPublication, "VexStatement", vexSubject);
        await approvals.RequestAsync(
            world.LeadDev, world.Scope, ApprovalKind.AttestationSignOff,
            "AttestationSnapshot", attestationSubject);

        Assert.Equal("pending publication",
            (await approvals.ForSubjectAsync("VexStatement", vexSubject))!.Qualifier);
        Assert.Equal("pending sign-off",
            (await approvals.ForSubjectAsync("AttestationSnapshot", attestationSubject))!.Qualifier);
    }

    [SkippableFact]
    public async Task Pending_states_for_a_page_come_back_in_one_lookup()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var approvals = scope.ServiceProvider.GetRequiredService<ApprovalService>();

        var second = Guid.NewGuid();
        await approvals.RequestAsync(
            world.LeadDev, world.Scope, ApprovalKind.PoamRiskAcceptance, "PoamItem", world.SubjectId);
        await approvals.RequestAsync(
            world.LeadDev, world.Scope, ApprovalKind.PoamCompletion, "PoamItem", second);

        var states = await approvals.ForSubjectsAsync("PoamItem", [world.SubjectId, second, Guid.NewGuid()]);

        Assert.Equal(2, states.Count);
    }

    // ---- Seed ---------------------------------------------------------------

    private sealed record World(
        Guid SubjectId, ScopeTarget Scope, Guid OtherInfoSecUserId,
        Principal Admin, Principal InfoSec, Principal LeadDev)
    {
        /// <summary>
        /// A scope-aware resolver, matching what PrincipalResolver actually
        /// does: roles resolve PER SCOPE, so a capability held on one project
        /// says nothing about another.
        ///
        /// A stub that returned the same principal for every scope would make
        /// "awaiting you" span the whole instance, and every other test's
        /// approvals would show up in this one.
        /// </summary>
        public Func<ScopeTarget, Task<Principal?>> ResolveFor(Principal principal) =>
            target => Task.FromResult(target.ProjectId == Scope.ProjectId ? principal : null);
    }

    private async Task<World> SeedAsync()
    {
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);

        var suffix = Guid.NewGuid().ToString("N")[..8];

        var client = new Client { Name = $"apr-client-{suffix}" };
        var project = new Project { ClientId = client.Id, Name = $"apr-project-{suffix}" };
        db.Clients.Add(client);
        db.Projects.Add(project);

        var infosec = new User
        {
            Login = $"apr-infosec-{suffix}", DisplayName = "InfoSec",
            Email = $"apr-infosec-{suffix}@example.test", IsApproved = true,
        };
        var lead = new User
        {
            Login = $"apr-lead-{suffix}", DisplayName = "Lead Dev",
            Email = $"apr-lead-{suffix}@example.test", IsApproved = true,
        };
        var other = new User
        {
            Login = $"apr-other-{suffix}", DisplayName = "Other InfoSec",
            Email = $"apr-other-{suffix}@example.test", IsApproved = true,
        };
        var admin = new User
        {
            Login = $"apr-admin-{suffix}", DisplayName = "Admin",
            Email = $"apr-admin-{suffix}@example.test", IsApproved = true, IsAdmin = true,
        };
        db.Users.AddRange(infosec, lead, other, admin);

        await db.SaveChangesAsync();

        return new World(
            Guid.NewGuid(),
            ScopeTarget.Project(client.Id, project.Id),
            other.Id,
            Admin: Principal.For(admin.Id, admin.Login, isAdmin: true, []),
            InfoSec: Principal.For(infosec.Id, infosec.Login, isAdmin: false, [ProjectRole.InfoSecOfficer]),
            LeadDev: Principal.For(lead.Id, lead.Login, isAdmin: false, [ProjectRole.LeadDev]));
    }
}
