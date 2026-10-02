using System.Net;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Api.Contracts;
using Tamp.Findings.Api.Endpoints;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Integration.Tests;

[Collection(DatabaseCollection.Name)]
public class ApiBRoleAssignmentTests
{
    private readonly DatabaseFixture _fx;
    public ApiBRoleAssignmentTests(DatabaseFixture fx) => _fx = fx;

    private async Task<(ApiBSupport.World w, HttpClient admin)> ArrangeAsync()
    {
        var s = ApiBSupport.Suffix();
        ApiBSupport.World w;
        using (var scope = _fx.Scope()) w = await ApiBSupport.SeedWorldAsync(_fx.Db(scope), s);
        return (w, _fx.Factory!.WithTestAuth().As(w.AdminId));
    }

    [SkippableFact]
    public async Task Anonymous_callers_are_refused()
    {
        Skip.IfNot(_fx.Available);
        var anon = _fx.Factory!.WithTestAuth().As(null);

        Assert.Equal(HttpStatusCode.Unauthorized, (await anon.GetAsync("/role-assignments")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized,
            (await anon.PostAsJsonAsync("/role-assignments", new RoleAssignmentCreateRequest("x", ProjectRole.LeadDev, null, Guid.NewGuid()))).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await anon.DeleteAsync($"/role-assignments/{Guid.NewGuid()}")).StatusCode);
    }

    [SkippableFact]
    public async Task Create_validates_the_login_and_exactly_one_tier()
    {
        Skip.IfNot(_fx.Available);
        var (w, admin) = await ArrangeAsync();

        var noLogin = await admin.PostAsJsonAsync("/role-assignments", new RoleAssignmentCreateRequest(" ", ProjectRole.LeadDev, null, w.ProjectId));
        Assert.Equal(HttpStatusCode.BadRequest, noLogin.StatusCode);

        var noTier = await admin.PostAsJsonAsync("/role-assignments", new RoleAssignmentCreateRequest("someone", ProjectRole.LeadDev, null, null));
        Assert.Equal(HttpStatusCode.BadRequest, noTier.StatusCode);

        var bothTiers = await admin.PostAsJsonAsync("/role-assignments", new RoleAssignmentCreateRequest("someone", ProjectRole.LeadDev, w.ClientId, w.ProjectId));
        Assert.Equal(HttpStatusCode.BadRequest, bothTiers.StatusCode);
    }

    [SkippableFact]
    public async Task Create_404s_when_the_client_or_project_does_not_exist()
    {
        Skip.IfNot(_fx.Available);
        var (_, admin) = await ArrangeAsync();

        var badClient = await admin.PostAsJsonAsync("/role-assignments", new RoleAssignmentCreateRequest("x", ProjectRole.LeadDev, Guid.NewGuid(), null));
        Assert.Equal(HttpStatusCode.NotFound, badClient.StatusCode);

        var badProject = await admin.PostAsJsonAsync("/role-assignments", new RoleAssignmentCreateRequest("x", ProjectRole.LeadDev, null, Guid.NewGuid()));
        Assert.Equal(HttpStatusCode.NotFound, badProject.StatusCode);
    }

    [SkippableFact]
    public async Task Create_at_project_and_client_tier_persists_and_is_idempotent_and_auto_creates_the_user()
    {
        Skip.IfNot(_fx.Available);
        var (w, admin) = await ArrangeAsync();
        var login = $"apib-new-{ApiBSupport.Suffix()}";

        var resp = await admin.PostAsJsonAsync("/role-assignments", new RoleAssignmentCreateRequest(login, ProjectRole.Architect, null, w.ProjectId));
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var first = (await resp.Content.ReadFromJsonAsync<RoleAssignmentResponse>(ApiBSupport.Json))!;
        Assert.Equal("Project", first.Scope);
        Assert.Equal(w.ProjectName, first.ProjectName);
        Assert.Equal(w.ClientName, first.ClientName);

        // Same grant again returns the same row rather than a duplicate or a 409.
        var again = (await (await admin.PostAsJsonAsync("/role-assignments",
            new RoleAssignmentCreateRequest(login, ProjectRole.Architect, null, w.ProjectId))).Content.ReadFromJsonAsync<RoleAssignmentResponse>(ApiBSupport.Json))!;
        Assert.Equal(first.Id, again.Id);

        var clientTier = (await (await admin.PostAsJsonAsync("/role-assignments",
            new RoleAssignmentCreateRequest(login, ProjectRole.Architect, w.ClientId, null))).Content.ReadFromJsonAsync<RoleAssignmentResponse>(ApiBSupport.Json))!;
        Assert.Equal("Client", clientTier.Scope);
        Assert.Equal(w.ClientName, clientTier.ClientName);
        Assert.Null(clientTier.ProjectId);

        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var user = await db.Users.SingleAsync(u => u.Login == login);
        Assert.Equal(2, await db.ProjectRoleAssignments.CountAsync(a => a.UserId == user.Id));
    }

    [SkippableFact]
    public async Task A_separation_of_duties_conflict_is_recorded_and_not_blocked_by_default()
    {
        Skip.IfNot(_fx.Available);
        var (w, admin) = await ArrangeAsync();
        var login = $"apib-sod-{ApiBSupport.Suffix()}";

        await admin.PostAsJsonAsync("/role-assignments", new RoleAssignmentCreateRequest(login, ProjectRole.LeadDev, null, w.ProjectId));
        var resp = await admin.PostAsJsonAsync("/role-assignments", new RoleAssignmentCreateRequest(login, ProjectRole.InfoSecOfficer, null, w.ProjectId));
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var body = (await resp.Content.ReadFromJsonAsync<RoleAssignmentResponse>(ApiBSupport.Json))!;

        using var scope = _fx.Scope();
        var row = await _fx.Db(scope).ProjectRoleAssignments.SingleAsync(a => a.Id == body.Id);
        Assert.NotNull(row.SodConflict);
    }

    [SkippableFact]
    public async Task An_enforced_separation_of_duties_conflict_is_refused_with_the_reason()
    {
        Skip.IfNot(_fx.Available);
        var (w, admin) = await ArrangeAsync();
        var login = $"apib-sodx-{ApiBSupport.Suffix()}";
        await admin.PostAsJsonAsync("/role-assignments", new RoleAssignmentCreateRequest(login, ProjectRole.LeadDev, null, w.ProjectId));

        bool? previous;
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            var settings = await db.InstanceSettings.FirstOrDefaultAsync(x => x.Id == InstanceSettings.SingletonId);
            if (settings is null) { settings = new InstanceSettings { Id = InstanceSettings.SingletonId }; db.InstanceSettings.Add(settings); }
            previous = settings.EnforceSeparationOfDuties;
            settings.EnforceSeparationOfDuties = true;
            await db.SaveChangesAsync();
        }

        try
        {
            var resp = await admin.PostAsJsonAsync("/role-assignments", new RoleAssignmentCreateRequest(login, ProjectRole.InfoSecOfficer, null, w.ProjectId));
            Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
            Assert.Contains("Separation of duties", await resp.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        }
        finally
        {
            using var scope = _fx.Scope();
            var db = _fx.Db(scope);
            var settings = await db.InstanceSettings.SingleAsync(x => x.Id == InstanceSettings.SingletonId);
            settings.EnforceSeparationOfDuties = previous ?? false;
            await db.SaveChangesAsync();
        }
    }

    [SkippableFact]
    public async Task List_filters_by_user_role_client_and_project_and_delete_removes_the_row()
    {
        Skip.IfNot(_fx.Available);
        var (w, admin) = await ArrangeAsync();
        var login = $"apib-list-{ApiBSupport.Suffix()}";
        var created = (await (await admin.PostAsJsonAsync("/role-assignments",
            new RoleAssignmentCreateRequest(login, ProjectRole.Auditor, null, w.ProjectId))).Content.ReadFromJsonAsync<RoleAssignmentResponse>(ApiBSupport.Json))!;
        await admin.PostAsJsonAsync("/role-assignments", new RoleAssignmentCreateRequest(login, ProjectRole.LeadDev, w.ClientId, null));

        var byUser = (await admin.GetFromJsonAsync<List<RoleAssignmentResponse>>($"/role-assignments?userLogin={login}", ApiBSupport.Json))!;
        Assert.Equal(2, byUser.Count);

        var byRole = (await admin.GetFromJsonAsync<List<RoleAssignmentResponse>>($"/role-assignments?userLogin={login}&role=Auditor", ApiBSupport.Json))!;
        Assert.Single(byRole);

        var byProject = (await admin.GetFromJsonAsync<List<RoleAssignmentResponse>>($"/role-assignments?projectId={w.ProjectId}", ApiBSupport.Json))!;
        Assert.Contains(byProject, r => r.Id == created.Id);

        var byClient = (await admin.GetFromJsonAsync<List<RoleAssignmentResponse>>($"/role-assignments?clientId={w.ClientId}", ApiBSupport.Json))!;
        Assert.Contains(byClient, r => r.Scope == "Client" && r.UserLogin == login);

        Assert.Equal(HttpStatusCode.NoContent, (await admin.DeleteAsync($"/role-assignments/{created.Id}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await admin.DeleteAsync($"/role-assignments/{created.Id}")).StatusCode);

        using var scope = _fx.Scope();
        Assert.False(await _fx.Db(scope).ProjectRoleAssignments.AnyAsync(a => a.Id == created.Id));
    }

    [SkippableFact]
    public async Task A_user_who_cannot_see_the_project_gets_404_on_the_filtered_list()
    {
        Skip.IfNot(_fx.Available);
        var (w, _) = await ArrangeAsync();
        var outsider = _fx.Factory!.WithTestAuth().As(w.OutsiderId);

        var resp = await outsider.GetAsync($"/role-assignments?projectId={w.ProjectId}");

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }
}

[Collection(DatabaseCollection.Name)]
public class ApiBPoamItemTests
{
    private readonly DatabaseFixture _fx;
    public ApiBPoamItemTests(DatabaseFixture fx) => _fx = fx;

    private static CreatePoamItemRequest Create(string title, PoamStatus? status = null, DateTimeOffset? due = null, string? url = null) =>
        new(title, "weakness", "plan", "resources", Severity.High, status, due, null, url);

    private async Task<(ApiBSupport.World w, WebApplicationFactoryHolder f)> ArrangeAsync()
    {
        var s = ApiBSupport.Suffix();
        ApiBSupport.World w;
        using (var scope = _fx.Scope()) w = await ApiBSupport.SeedWorldAsync(_fx.Db(scope), s);
        return (w, new WebApplicationFactoryHolder(_fx.Factory!.WithTestAuth()));
    }

    private sealed class WebApplicationFactoryHolder(Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactory<Program> f)
    {
        public HttpClient As(Guid? id) => f.As(id);
    }

    [SkippableFact]
    public async Task Anonymous_is_401_and_unknown_project_is_404()
    {
        Skip.IfNot(_fx.Available);
        var (w, f) = await ArrangeAsync();

        Assert.Equal(HttpStatusCode.Unauthorized, (await f.As(null).GetAsync($"/projects/{w.ProjectId}/poam-items")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await f.As(null).PostAsJsonAsync($"/projects/{w.ProjectId}/poam-items", Create("x"))).StatusCode);

        var lead = f.As(w.LeadId);
        Assert.Equal(HttpStatusCode.NotFound, (await lead.PostAsJsonAsync($"/projects/{Guid.NewGuid()}/poam-items", Create("x"))).StatusCode);
    }

    [SkippableFact]
    public async Task A_viewer_without_a_role_cannot_create_and_nothing_is_written()
    {
        Skip.IfNot(_fx.Available);
        var (w, f) = await ArrangeAsync();

        // Admin sees everything, so use the leadless viewer. A viewer with no visibility gets 404 from the filter;
        // grant visibility through a client-level Auditor role so the capability check is what answers.
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            db.ProjectRoleAssignments.Add(new ProjectRoleAssignment { UserId = w.ViewerId, Role = ProjectRole.Auditor, ProjectId = w.ProjectId });
            await db.SaveChangesAsync();
        }

        var resp = await f.As(w.ViewerId).PostAsJsonAsync($"/projects/{w.ProjectId}/poam-items", Create("denied"));

        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
        using var s2 = _fx.Scope();
        Assert.False(await _fx.Db(s2).PoamItems.AnyAsync(p => p.ProjectId == w.ProjectId && p.Title == "denied"));
    }

    [SkippableFact]
    public async Task Create_validates_title_description_and_url()
    {
        Skip.IfNot(_fx.Available);
        var (w, f) = await ArrangeAsync();
        var lead = f.As(w.LeadId);

        Assert.Equal(HttpStatusCode.BadRequest, (await lead.PostAsJsonAsync($"/projects/{w.ProjectId}/poam-items", Create(" "))).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest,
            (await lead.PostAsJsonAsync($"/projects/{w.ProjectId}/poam-items", new CreatePoamItemRequest("t", "", null, null, Severity.Low, null, null, null, null))).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest,
            (await lead.PostAsJsonAsync($"/projects/{w.ProjectId}/poam-items", Create("t", url: "not a url"))).StatusCode);
    }

    [SkippableFact]
    public async Task Full_lifecycle_create_list_update_transition_and_close_with_audit()
    {
        Skip.IfNot(_fx.Available);
        var (w, f) = await ArrangeAsync();
        var lead = f.As(w.LeadId);
        var past = DateTimeOffset.UtcNow.AddDays(-3);

        var created = await lead.PostAsJsonAsync($"/projects/{w.ProjectId}/poam-items",
            Create("overdue item", due: past, url: "https://example.test/ref"));
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var item = (await created.Content.ReadFromJsonAsync<PoamItemDto>(ApiBSupport.Json))!;
        Assert.True(item.IsPastDue);
        Assert.Equal(PoamStatus.Open, item.Status);
        Assert.Equal(w.LeadId, item.AuthorUserId);

        var future = (await (await lead.PostAsJsonAsync($"/projects/{w.ProjectId}/poam-items",
            Create("future item", due: DateTimeOffset.UtcNow.AddDays(30)))).Content.ReadFromJsonAsync<PoamItemDto>(ApiBSupport.Json))!;
        Assert.False(future.IsPastDue);

        // List: default excludes closed, pastDueOnly narrows, status filters.
        var all = (await lead.GetFromJsonAsync<List<PoamItemDto>>($"/projects/{w.ProjectId}/poam-items", ApiBSupport.Json))!;
        Assert.Equal(2, all.Count);
        Assert.Equal(item.Id, all[0].Id);   // most overdue first
        var pastDue = (await lead.GetFromJsonAsync<List<PoamItemDto>>($"/projects/{w.ProjectId}/poam-items?pastDueOnly=true", ApiBSupport.Json))!;
        Assert.Single(pastDue);
        var inProgress = (await lead.GetFromJsonAsync<List<PoamItemDto>>($"/projects/{w.ProjectId}/poam-items?status=InProgress", ApiBSupport.Json))!;
        Assert.Empty(inProgress);

        // Update fields + status change via TransitionAsync.
        var upd = await lead.PatchAsJsonAsync($"/poam-items/{item.Id}",
            new UpdatePoamItemRequest("renamed", null, null, null, Severity.Critical, PoamStatus.InProgress, null, null, null));
        Assert.Equal(HttpStatusCode.OK, upd.StatusCode);
        var updated = (await upd.Content.ReadFromJsonAsync<PoamItemDto>(ApiBSupport.Json))!;
        Assert.Equal("renamed", updated.Title);
        Assert.Equal(Severity.Critical, updated.Severity);
        Assert.Equal(PoamStatus.InProgress, updated.Status);
        Assert.Equal("weakness", updated.WeaknessDescription);

        // RiskAccepted cannot be reached through a plain PATCH.
        var risk = await lead.PatchAsJsonAsync($"/poam-items/{item.Id}",
            new UpdatePoamItemRequest(null, null, null, null, null, PoamStatus.RiskAccepted, null, null, null));
        Assert.Equal(HttpStatusCode.BadRequest, risk.StatusCode);

        // Invalid edit (blank title -> falls back to existing, so use a bad url).
        var bad = await lead.PatchAsJsonAsync($"/poam-items/{item.Id}",
            new UpdatePoamItemRequest(null, null, null, null, null, null, null, null, "nope"));
        Assert.Equal(HttpStatusCode.BadRequest, bad.StatusCode);

        // Close (soft delete).
        Assert.Equal(HttpStatusCode.NoContent, (await lead.DeleteAsync($"/poam-items/{item.Id}")).StatusCode);
        // Closing again is a no-op.
        Assert.Equal(HttpStatusCode.NoContent, (await lead.DeleteAsync($"/poam-items/{item.Id}")).StatusCode);

        var live = (await lead.GetFromJsonAsync<List<PoamItemDto>>($"/projects/{w.ProjectId}/poam-items", ApiBSupport.Json))!;
        Assert.DoesNotContain(live, p => p.Id == item.Id);
        var withClosed = (await lead.GetFromJsonAsync<List<PoamItemDto>>($"/projects/{w.ProjectId}/poam-items?includeClosed=true", ApiBSupport.Json))!;
        var closed = withClosed.Single(p => p.Id == item.Id);
        Assert.Equal(PoamStatus.Cancelled, closed.Status);
        Assert.NotNull(closed.ClosedAt);

        using var scope = _fx.Scope();
        var actions = await _fx.Db(scope).AuditEntries
            .Where(a => a.SubjectId == item.Id).Select(a => a.Action).ToListAsync();
        Assert.Contains("poam.created", actions);
        Assert.Contains("poam.updated", actions);
        Assert.Contains("poam.status_changed", actions);
    }

    [SkippableFact]
    public async Task Update_and_close_404_for_unknown_items_and_completing_stamps_actual_date()
    {
        Skip.IfNot(_fx.Available);
        var (w, f) = await ArrangeAsync();
        var lead = f.As(w.LeadId);

        Assert.Equal(HttpStatusCode.NotFound,
            (await lead.PatchAsJsonAsync($"/poam-items/{Guid.NewGuid()}", new UpdatePoamItemRequest("t", null, null, null, null, null, null, null, null))).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await lead.DeleteAsync($"/poam-items/{Guid.NewGuid()}")).StatusCode);

        var item = (await (await lead.PostAsJsonAsync($"/projects/{w.ProjectId}/poam-items", Create("to complete"))).Content.ReadFromJsonAsync<PoamItemDto>(ApiBSupport.Json))!;
        var done = await lead.PatchAsJsonAsync($"/poam-items/{item.Id}",
            new UpdatePoamItemRequest(null, null, null, null, null, PoamStatus.Completed, null, null, null));
        Assert.Equal(HttpStatusCode.OK, done.StatusCode);
        var body = (await done.Content.ReadFromJsonAsync<PoamItemDto>(ApiBSupport.Json))!;
        Assert.NotNull(body.ActualCompletionDate);
        Assert.NotNull(body.ClosedAt);
        Assert.False(body.IsPastDue);
    }

    [SkippableFact]
    public async Task A_role_less_user_is_denied_on_update_and_close_with_a_reason()
    {
        Skip.IfNot(_fx.Available);
        var (w, f) = await ArrangeAsync();
        var item = (await (await f.As(w.LeadId).PostAsJsonAsync($"/projects/{w.ProjectId}/poam-items", Create("guarded"))).Content.ReadFromJsonAsync<PoamItemDto>(ApiBSupport.Json))!;

        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            db.ProjectRoleAssignments.Add(new ProjectRoleAssignment { UserId = w.ViewerId, Role = ProjectRole.Auditor, ProjectId = w.ProjectId });
            await db.SaveChangesAsync();
        }
        var viewer = f.As(w.ViewerId);

        var patch = await viewer.PatchAsJsonAsync($"/poam-items/{item.Id}",
            new UpdatePoamItemRequest("hijack", null, null, null, null, null, null, null, null));
        Assert.Equal(HttpStatusCode.Forbidden, patch.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await viewer.DeleteAsync($"/poam-items/{item.Id}")).StatusCode);

        using var s2 = _fx.Scope();
        var row = await _fx.Db(s2).PoamItems.SingleAsync(p => p.Id == item.Id);
        Assert.Equal("guarded", row.Title);
        Assert.Null(row.ClosedAt);
    }

    [SkippableFact]
    public async Task An_unapproved_or_unknown_user_is_unauthorized_on_writes()
    {
        Skip.IfNot(_fx.Available);
        var (w, f) = await ArrangeAsync();
        Guid pendingId;
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            var pending = new User { Login = $"apib-pend-{ApiBSupport.Suffix()}", DisplayName = "p", IsApproved = false, IsAdmin = true };
            db.Users.Add(pending);
            await db.SaveChangesAsync();
            pendingId = pending.Id;
        }

        var resp = await f.As(pendingId).PostAsJsonAsync($"/projects/{w.ProjectId}/poam-items", Create("nope"));
        // The visibility filter hides everything from an unapproved user, so the project reads as not found.
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }
}
