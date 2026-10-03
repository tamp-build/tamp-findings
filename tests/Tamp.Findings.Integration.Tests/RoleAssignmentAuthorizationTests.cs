using System.Net;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Api.Contracts;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Integration.Tests;

// TFND-228: POST/GET/DELETE /role-assignments used to require only a signed-in, approved user. Granting,
// revoking and listing roles is an access-control decision, so each must be authorized with AssignRoles at the
// scope it acts on (Admin / InfoSec), resolved from the cookie and never from the request body.
[Collection(DatabaseCollection.Name)]
public class RoleAssignmentAuthorizationTests
{
    private readonly DatabaseFixture _fx;
    public RoleAssignmentAuthorizationTests(DatabaseFixture fx) => _fx = fx;

    private sealed record Arrangement(ApiBSupport.World W, Guid OtherClientId, Guid OtherProjectId, Guid InfoSecId);

    private async Task<Arrangement> ArrangeAsync()
    {
        var s = ApiBSupport.Suffix();
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var w = await ApiBSupport.SeedWorldAsync(db, s);
        // An InfoSecOfficer on THIS project only, and a second client + project they have no role on.
        var infosec = new User { Login = $"ra-infosec-{s}", DisplayName = "infosec", Email = $"i{s}@e.test", IsApproved = true };
        var other = new Client { Name = $"ra-other-{s}" };
        var otherProject = new Project { ClientId = other.Id, Name = $"ra-otherp-{s}" };
        db.Users.Add(infosec); db.Clients.Add(other); db.Projects.Add(otherProject);
        db.ProjectRoleAssignments.Add(new ProjectRoleAssignment { UserId = infosec.Id, Role = ProjectRole.InfoSecOfficer, ProjectId = w.ProjectId });
        await db.SaveChangesAsync();
        return new Arrangement(w, other.Id, otherProject.Id, infosec.Id);
    }

    private HttpClient As(Guid userId) => _fx.Factory!.WithTestAuth().As(userId);

    private static RoleAssignmentCreateRequest Grant(string login, ProjectRole role, Guid? clientId, Guid? projectId) =>
        new(login, role, clientId, projectId);

    private async Task<bool> HasAssignmentAsync(string login, ProjectRole role)
    {
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        return await db.ProjectRoleAssignments.AnyAsync(a => a.Role == role && db.Users.Any(u => u.Id == a.UserId && u.Login == login));
    }

    [SkippableFact]
    public async Task A_signed_in_user_with_no_role_cannot_grant_and_nothing_is_created()
    {
        Skip.IfNot(_fx.Available);
        var a = await ArrangeAsync();
        var login = $"victim-{ApiBSupport.Suffix()}";

        var resp = await As(a.W.ViewerId).PostAsJsonAsync("/role-assignments", Grant(login, ProjectRole.InfoSecOfficer, null, a.W.ProjectId));

        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
        using var scope = _fx.Scope();
        Assert.False(await _fx.Db(scope).Users.AnyAsync(u => u.Login == login), "an unauthorized caller must not even pre-provision a user");
    }

    [SkippableFact]
    public async Task A_lead_dev_cannot_escalate_themselves()
    {
        Skip.IfNot(_fx.Available);
        var a = await ArrangeAsync();
        string leadLogin;
        using (var scope = _fx.Scope()) leadLogin = (await _fx.Db(scope).Users.FirstAsync(u => u.Id == a.W.LeadId)).Login;

        var resp = await As(a.W.LeadId).PostAsJsonAsync("/role-assignments", Grant(leadLogin, ProjectRole.InfoSecOfficer, null, a.W.ProjectId));

        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
        Assert.False(await HasAssignmentAsync(leadLogin, ProjectRole.InfoSecOfficer));
    }

    [SkippableFact]
    public async Task An_outsider_with_a_role_elsewhere_cannot_grant_on_this_project()
    {
        Skip.IfNot(_fx.Available);
        var a = await ArrangeAsync();

        var resp = await As(a.W.OutsiderId).PostAsJsonAsync("/role-assignments", Grant($"x-{ApiBSupport.Suffix()}", ProjectRole.LeadDev, null, a.W.ProjectId));

        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [SkippableFact]
    public async Task An_infosec_officer_can_grant_at_their_own_project_but_not_at_another_project_or_client()
    {
        Skip.IfNot(_fx.Available);
        var a = await ArrangeAsync();
        var http = As(a.InfoSecId);
        var login = $"grantee-{ApiBSupport.Suffix()}";

        var ok = await http.PostAsJsonAsync("/role-assignments", Grant(login, ProjectRole.LeadDev, null, a.W.ProjectId));
        var otherProject = await http.PostAsJsonAsync("/role-assignments", Grant(login, ProjectRole.LeadDev, null, a.OtherProjectId));
        var otherClient = await http.PostAsJsonAsync("/role-assignments", Grant(login, ProjectRole.LeadDev, a.OtherClientId, null));
        // Widening the tier by claiming the whole client in the body must not work either: the scope in the body
        // is what gets authorized, and this officer holds no role at the client.
        var wholeClient = await http.PostAsJsonAsync("/role-assignments", Grant(login, ProjectRole.LeadDev, a.W.ClientId, null));

        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, otherProject.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, otherClient.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, wholeClient.StatusCode);
    }

    [SkippableFact]
    public async Task An_admin_can_grant_and_the_grant_is_audited()
    {
        Skip.IfNot(_fx.Available);
        var a = await ArrangeAsync();
        var login = $"admin-granted-{ApiBSupport.Suffix()}";

        var resp = await As(a.W.AdminId).PostAsJsonAsync("/role-assignments", Grant(login, ProjectRole.Architect, null, a.W.ProjectId));

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.True(await HasAssignmentAsync(login, ProjectRole.Architect));
        using var scope = _fx.Scope();
        Assert.True(await _fx.Db(scope).AuditEntries.AnyAsync(e => e.Action == "role.granted" && e.Detail!.Contains(login)),
            "granting through the endpoint must leave the same audit trail as the UI");
    }

    [SkippableFact]
    public async Task Listing_role_assignments_needs_AssignRoles_at_the_scope_listed()
    {
        Skip.IfNot(_fx.Available);
        var a = await ArrangeAsync();

        var viewerProject = await As(a.W.ViewerId).GetAsync($"/role-assignments?projectId={a.W.ProjectId}");
        var leadProject = await As(a.W.LeadId).GetAsync($"/role-assignments?projectId={a.W.ProjectId}");
        var leadUnfiltered = await As(a.W.LeadId).GetAsync("/role-assignments");
        var infosecOwnProject = await As(a.InfoSecId).GetAsync($"/role-assignments?projectId={a.W.ProjectId}");
        var infosecUnfiltered = await As(a.InfoSecId).GetAsync("/role-assignments");
        var adminUnfiltered = await As(a.W.AdminId).GetAsync("/role-assignments");

        // A caller who cannot even see the project gets the existing 404 (no existence leak); one who can see it
        // but lacks AssignRoles gets 403. Either way, nothing is listed.
        Assert.Contains(viewerProject.StatusCode, new[] { HttpStatusCode.Forbidden, HttpStatusCode.NotFound });
        Assert.Equal(HttpStatusCode.Forbidden, leadProject.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, leadUnfiltered.StatusCode);
        Assert.Equal(HttpStatusCode.OK, infosecOwnProject.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, infosecUnfiltered.StatusCode);   // instance-wide listing is an admin act
        Assert.Equal(HttpStatusCode.OK, adminUnfiltered.StatusCode);
    }

    [SkippableFact]
    public async Task A_lead_dev_cannot_revoke_an_assignment_but_an_admin_can()
    {
        Skip.IfNot(_fx.Available);
        var a = await ArrangeAsync();
        var login = $"revokee-{ApiBSupport.Suffix()}";
        var created = (await (await As(a.W.AdminId).PostAsJsonAsync("/role-assignments", Grant(login, ProjectRole.LeadDev, null, a.W.ProjectId)))
            .Content.ReadFromJsonAsync<RoleAssignmentResponse>(ApiBSupport.Json))!;

        var byLead = await As(a.W.LeadId).DeleteAsync($"/role-assignments/{created.Id}");
        var byOutsider = await As(a.W.OutsiderId).DeleteAsync($"/role-assignments/{created.Id}");
        Assert.Equal(HttpStatusCode.Forbidden, byLead.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, byOutsider.StatusCode);
        Assert.True(await HasAssignmentAsync(login, ProjectRole.LeadDev), "an unauthorized revoke must leave the assignment in place");

        var byAdmin = await As(a.W.AdminId).DeleteAsync($"/role-assignments/{created.Id}");
        Assert.Equal(HttpStatusCode.NoContent, byAdmin.StatusCode);
        Assert.False(await HasAssignmentAsync(login, ProjectRole.LeadDev));
    }

    [SkippableFact]
    public async Task Granting_the_same_role_twice_stays_idempotent_for_an_authorized_caller()
    {
        Skip.IfNot(_fx.Available);
        var a = await ArrangeAsync();
        var http = As(a.W.AdminId);
        var login = $"idem-{ApiBSupport.Suffix()}";

        var first = (await (await http.PostAsJsonAsync("/role-assignments", Grant(login, ProjectRole.LeadDev, null, a.W.ProjectId)))
            .Content.ReadFromJsonAsync<RoleAssignmentResponse>(ApiBSupport.Json))!;
        var again = await http.PostAsJsonAsync("/role-assignments", Grant(login, ProjectRole.LeadDev, null, a.W.ProjectId));

        Assert.Equal(HttpStatusCode.OK, again.StatusCode);
        Assert.Equal(first.Id, (await again.Content.ReadFromJsonAsync<RoleAssignmentResponse>(ApiBSupport.Json))!.Id);
    }
}
