using System.Net;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Approvals;
using Tamp.Findings.Application.Compliance;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Risk;
using Tamp.Findings.Domain.Values;
using static Tamp.Findings.Integration.Tests.ApiAHarness;

namespace Tamp.Findings.Integration.Tests;

/// <summary>
/// The review-gated project downgrade (ADR 0015 §5, TFND-219).
///
/// The downgrade case needs a project whose INHERITED stack really does assert
/// something stricter, and the Library archetype is the honest example: a code library
/// inherits the runtime access-control family it never implements, so AC-2 arrives as
/// Inherited. A project then saying "N/A here" is a genuine downgrade.
///
/// An unclassified project fails upward to the Service archetype, which asserts no
/// dispositions at all (a service owns everything), so nothing it authors is a
/// downgrade — which is why none of the pre-existing authoring tests change.
/// </summary>
[Collection(DatabaseCollection.Name)]
public class ApiBControlDowngradeTests
{
    private readonly DatabaseFixture _fx;
    public ApiBControlDowngradeTests(DatabaseFixture fx) => _fx = fx;

    /// <summary>A Library project — one whose archetype inherits AC-2.</summary>
    private async Task<Tree> LibraryAsync()
    {
        var tree = await ClientProjectAsync(_fx);
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var project = await db.Projects.SingleAsync(p => p.Id == tree.ProjectId);
        project.Archetype = ProjectArchetype.Library;
        await db.SaveChangesAsync();
        return tree;
    }

    private static object Dispositions(params object[] d) => new { dispositions = d };

    [SkippableFact]
    public async Task Authoring_a_downgrade_is_refused_and_names_what_it_would_weaken()
    {
        Skip.IfNot(_fx.Available);
        var tree = await LibraryAsync();
        var admin = Http(_fx, await UserAsync(_fx, admin: true));

        // This used to return 200, store the assertion, and then silently lose the
        // harden-only merge. A write that reports success and changes nothing an
        // operator can see is worse than a refusal.
        var response = await admin.PatchAsJsonAsync(
            $"/projects/{tree.ProjectId}/control-dispositions",
            Dispositions(new { controlIds = new[] { "AC-2" }, kind = "NotApplicable", justification = "no accounts here" }));

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("AC-2", body, StringComparison.Ordinal);
        Assert.Contains("Inherited", body, StringComparison.Ordinal);
        // The layer is named, so the refusal says WHERE the stricter claim comes from.
        Assert.Contains("archetype: library", body, StringComparison.Ordinal);
        Assert.Contains("downgrades", body, StringComparison.Ordinal);

        // And nothing was written -- not even the controls in the same batch that would
        // have been fine, because half a batch applied is a state nobody asked for.
        using var scope = _fx.Scope();
        var project = await _fx.Db(scope).Projects.AsNoTracking().SingleAsync(p => p.Id == tree.ProjectId);
        Assert.True(project.PolicyLayer is null || project.PolicyLayer.Assertions.Count == 0);
    }

    [SkippableFact]
    public async Task A_batch_containing_one_downgrade_writes_none_of_it()
    {
        Skip.IfNot(_fx.Available);
        var tree = await LibraryAsync();
        var admin = Http(_fx, await UserAsync(_fx, admin: true));

        var response = await admin.PatchAsJsonAsync(
            $"/projects/{tree.ProjectId}/control-dispositions",
            Dispositions(
                // A fill: the Library archetype says nothing about CM-8.
                new { controlIds = new[] { "CM-8" }, kind = "Gated", gates = new[] { GateKeys.CriticalCves } },
                new { controlIds = new[] { "AC-2" }, kind = "NotApplicable", justification = "no accounts here" }));

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        using var scope = _fx.Scope();
        var project = await _fx.Db(scope).Projects.AsNoTracking().SingleAsync(p => p.Id == tree.ProjectId);
        Assert.True(project.PolicyLayer is null || project.PolicyLayer.Assertions.Count == 0);
    }

    [SkippableFact]
    public async Task A_fill_and_an_upgrade_still_go_straight_through()
    {
        Skip.IfNot(_fx.Available);
        var tree = await LibraryAsync();
        var admin = Http(_fx, await UserAsync(_fx, admin: true));

        // The whole point of ADR 0015 §4: these need no precedence and no reviewer. A
        // Gated claim on an Inherited default is the tamp-http SC-13 case -- strictest
        // wins already, so nobody has to approve a project taking MORE responsibility.
        var response = await admin.PatchAsJsonAsync(
            $"/projects/{tree.ProjectId}/control-dispositions",
            Dispositions(
                new { controlIds = new[] { "CM-8" }, kind = "Gated", gates = new[] { GateKeys.CriticalCves } },
                new { controlIds = new[] { "AC-2" }, kind = "Gated", gates = new[] { GateKeys.VerifiedSecrets } }));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        using var scope = _fx.Scope();
        var project = await _fx.Db(scope).Projects.AsNoTracking().SingleAsync(p => p.Id == tree.ProjectId);
        Assert.Equal(2, project.PolicyLayer!.Assertions.Count);
        // And the authoring path cannot set the override flag -- that is what keeps the
        // merge's single exception behind a reviewer.
        Assert.All(project.PolicyLayer.Assertions, a => Assert.False(a.Overrides));
    }

    [SkippableFact]
    public async Task Requesting_a_downgrade_files_an_approval_and_writes_nothing_yet()
    {
        Skip.IfNot(_fx.Available);
        var tree = await LibraryAsync();
        var admin = Http(_fx, await UserAsync(_fx, admin: true));

        var response = await admin.PostAsJsonAsync(
            $"/projects/{tree.ProjectId}/control-dispositions/downgrades",
            new { controlId = "AC-2", kind = "NotApplicable", justification = "This library holds no accounts." });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<Dictionary<string, object>>();
        Assert.Equal("AC-2", body!["controlId"].ToString());
        Assert.Contains("downgrade", body["qualifier"].ToString()!, StringComparison.Ordinal);

        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var pending = await db.PendingApprovals.AsNoTracking().SingleAsync(
            a => a.ProjectId == tree.ProjectId && a.Kind == ApprovalKind.ControlDispositionDowngrade);
        Assert.Equal(ApprovalState.Pending, pending.State);
        // The conflict is on the request the reviewer reads, so they do not have to go
        // and work out what it weakens.
        Assert.Contains("Inherited", pending.Justification!, StringComparison.Ordinal);

        var project = await db.Projects.AsNoTracking().SingleAsync(p => p.Id == tree.ProjectId);
        Assert.True(project.PolicyLayer is null || project.PolicyLayer.Assertions.Count == 0);
    }

    [SkippableFact]
    public async Task Approving_it_writes_the_override_and_the_disposition_actually_changes()
    {
        Skip.IfNot(_fx.Available);
        var tree = await LibraryAsync();
        var admin = Http(_fx, await UserAsync(_fx, admin: true));

        await admin.PostAsJsonAsync(
            $"/projects/{tree.ProjectId}/control-dispositions/downgrades",
            new { controlId = "AC-2", kind = "NotApplicable", justification = "This library holds no accounts." });

        Guid approvalId;
        using (var read = _fx.Scope())
            approvalId = (await _fx.Db(read).PendingApprovals.AsNoTracking().SingleAsync(
                a => a.ProjectId == tree.ProjectId && a.Kind == ApprovalKind.ControlDispositionDowngrade)).Id;

        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var actors = await AppCovSeed.UsersAsync(db);
        var approvals = scope.ServiceProvider.GetRequiredService<ApprovalService>();

        var decided = await approvals.DecideAsync(actors.InfoSec, approvalId, approve: true, note: "Agreed.");
        Assert.True(decided.Success, decided.Error);

        var project = await db.Projects.AsNoTracking().SingleAsync(p => p.Id == tree.ProjectId);
        var assertion = Assert.Single(project.PolicyLayer!.Assertions);
        Assert.Equal(ControlDispositionKind.NotApplicable, assertion.Kind);
        Assert.True(assertion.Overrides);

        // It is not enough that the row exists -- the resolved policy has to agree, or
        // the approval moved a flag and nothing else.
        var policy = scope.ServiceProvider.GetRequiredService<Application.Policy.PolicyResolver>();
        var effective = await policy.ForProjectAsync(tree.ProjectId);
        Assert.Equal(ControlDispositionKind.NotApplicable, effective.Assertions["AC-2"].Kind);
        Assert.True(effective.Assertions["AC-2"].Overridden);

        // And it is audited against the project, with what was weakened.
        var entry = await db.AuditEntries.AsNoTracking().SingleAsync(
            a => a.SubjectId == tree.ProjectId && a.Action == "controldisposition.downgraded");
        Assert.Contains("AC-2", entry.Detail!, StringComparison.Ordinal);
    }

    [SkippableFact]
    public async Task Declining_it_leaves_the_stricter_default_in_place()
    {
        Skip.IfNot(_fx.Available);
        var tree = await LibraryAsync();
        var admin = Http(_fx, await UserAsync(_fx, admin: true));

        await admin.PostAsJsonAsync(
            $"/projects/{tree.ProjectId}/control-dispositions/downgrades",
            new { controlId = "AC-2", kind = "NotApplicable", justification = "This library holds no accounts." });

        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var actors = await AppCovSeed.UsersAsync(db);
        var approvals = scope.ServiceProvider.GetRequiredService<ApprovalService>();
        var approvalId = (await db.PendingApprovals.AsNoTracking().SingleAsync(
            a => a.ProjectId == tree.ProjectId && a.Kind == ApprovalKind.ControlDispositionDowngrade)).Id;

        Assert.True((await approvals.DecideAsync(actors.InfoSec, approvalId, approve: false, note: "It does hold accounts.")).Success);

        var project = await db.Projects.AsNoTracking().SingleAsync(p => p.Id == tree.ProjectId);
        Assert.True(project.PolicyLayer is null || project.PolicyLayer.Assertions.Count == 0);

        var policy = scope.ServiceProvider.GetRequiredService<Application.Policy.PolicyResolver>();
        var effective = await policy.ForProjectAsync(tree.ProjectId);
        Assert.Equal(ControlDispositionKind.Inherited, effective.Assertions["AC-2"].Kind);
    }

    [SkippableFact]
    public async Task An_admin_cannot_approve_their_own_downgrade()
    {
        Skip.IfNot(_fx.Available);
        var tree = await LibraryAsync();
        var adminId = await UserAsync(_fx, admin: true);

        await Http(_fx, adminId).PostAsJsonAsync(
            $"/projects/{tree.ProjectId}/control-dispositions/downgrades",
            new { controlId = "AC-2", kind = "NotApplicable", justification = "This library holds no accounts." });

        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var approvals = scope.ServiceProvider.GetRequiredService<ApprovalService>();
        var principals = scope.ServiceProvider.GetRequiredService<Application.Authorization.PrincipalResolver>();
        var approvalId = (await db.PendingApprovals.AsNoTracking().SingleAsync(
            a => a.ProjectId == tree.ProjectId && a.Kind == ApprovalKind.ControlDispositionDowngrade)).Id;

        // Two independent reasons this must fail, and both matter. The deciding
        // capability is AcceptRisk, which Admin deliberately does not hold; and even if
        // it did, ApprovalService refuses self-approval. An admin who could complete
        // their own loosening is the thing ADR 0015 §5 is for.
        var actor = await principals.ResolveAsync(
            adminId, Application.Authorization.ScopeTarget.Project(tree.ClientId, tree.ProjectId));
        var decided = await approvals.DecideAsync(actor!, approvalId, approve: true);

        Assert.False(decided.Success);
        var project = await db.Projects.AsNoTracking().SingleAsync(p => p.Id == tree.ProjectId);
        Assert.True(project.PolicyLayer is null || project.PolicyLayer.Assertions.Count == 0);
    }

    [SkippableFact]
    public async Task Requesting_something_that_is_not_a_downgrade_is_refused_as_pointless()
    {
        Skip.IfNot(_fx.Available);
        var tree = await LibraryAsync();
        var admin = Http(_fx, await UserAsync(_fx, admin: true));

        // CM-8 is not asserted by the Library archetype, so this is a fill. Putting it
        // in a reviewer's queue would waste their attention on a decision the authoring
        // endpoint takes immediately.
        var response = await admin.PostAsJsonAsync(
            $"/projects/{tree.ProjectId}/control-dispositions/downgrades",
            new { controlId = "CM-8", kind = "NotApplicable", justification = "no inventory" });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("not a downgrade", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
    }

    [SkippableFact]
    public async Task A_downgrade_request_needs_a_justification_and_a_real_kind()
    {
        Skip.IfNot(_fx.Available);
        var tree = await LibraryAsync();
        var admin = Http(_fx, await UserAsync(_fx, admin: true));
        var url = $"/projects/{tree.ProjectId}/control-dispositions/downgrades";

        Assert.Equal(HttpStatusCode.BadRequest, (await admin.PostAsJsonAsync(url,
            new { controlId = "AC-2", kind = "Sideways", justification = "x" })).StatusCode);

        // The justification is what the reviewer decides on, so an empty one makes the
        // request undecidable rather than merely untidy.
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.PostAsJsonAsync(url,
            new { controlId = "AC-2", kind = "NotApplicable", justification = "  " })).StatusCode);
    }

    [SkippableFact]
    public async Task A_second_request_for_the_same_control_is_refused()
    {
        Skip.IfNot(_fx.Available);
        var tree = await LibraryAsync();
        var admin = Http(_fx, await UserAsync(_fx, admin: true));
        var url = $"/projects/{tree.ProjectId}/control-dispositions/downgrades";
        object Body(string control) => new { controlId = control, kind = "NotApplicable", justification = "no accounts" };

        Assert.Equal(HttpStatusCode.OK, (await admin.PostAsJsonAsync(url, Body("AC-2"))).StatusCode);

        // The subject id is derived from (project, control), so ApprovalService's own
        // duplicate guard applies: two live requests would let a second reviewer approve
        // the copy of a decision the first one is still looking at.
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.PostAsJsonAsync(url, Body("ac-2"))).StatusCode);

        using var scope = _fx.Scope();
        Assert.Equal(1, await _fx.Db(scope).PendingApprovals.CountAsync(
            a => a.ProjectId == tree.ProjectId && a.Kind == ApprovalKind.ControlDispositionDowngrade));
    }

    [SkippableFact]
    public async Task A_non_admin_cannot_request_one()
    {
        Skip.IfNot(_fx.Available);
        var tree = await LibraryAsync();
        var userId = await UserAsync(_fx, admin: false);
        await GrantAsync(_fx, userId, ProjectRole.LeadDev, tree.ClientId, null);

        var response = await Http(_fx, userId).PostAsJsonAsync(
            $"/projects/{tree.ProjectId}/control-dispositions/downgrades",
            new { controlId = "AC-2", kind = "NotApplicable", justification = "no accounts" });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [SkippableFact]
    public async Task The_pending_lookup_finds_the_request_by_control_id()
    {
        Skip.IfNot(_fx.Available);
        var tree = await LibraryAsync();
        var admin = Http(_fx, await UserAsync(_fx, admin: true));

        await admin.PostAsJsonAsync(
            $"/projects/{tree.ProjectId}/control-dispositions/downgrades",
            new { controlId = "AC-2", kind = "NotApplicable", justification = "no accounts" });

        using var scope = _fx.Scope();
        var downgrades = scope.ServiceProvider.GetRequiredService<ControlDowngradeService>();

        // Keyed off the payload rather than the subject id, which is a one-way hash, and
        // case-insensitive because a control id is written both ways in the wild.
        var pending = await downgrades.PendingAsync(tree.ProjectId);
        Assert.True(pending.ContainsKey("AC-2"));
        Assert.True(pending.ContainsKey("ac-2"));
    }
}
