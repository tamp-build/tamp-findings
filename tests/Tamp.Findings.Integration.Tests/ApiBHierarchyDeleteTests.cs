using System.Net;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Domain.Values;
using static Tamp.Findings.Integration.Tests.ApiAHarness;

namespace Tamp.Findings.Integration.Tests;

/// <summary>
/// Deleting hierarchy over HTTP (TFND-169).
///
/// There was no application path to remove a client or a project. Clearing one stale,
/// misnamed project meant a raw cascade DELETE against the lab's Postgres over kubectl
/// — the most destructive operation in the product, performed by the least supervised
/// route, leaving no audit row.
///
/// These cover the route, and more importantly the three properties that make it safe
/// to expose at all: the authority required, the confirmation actually confirming, and
/// the audit record outliving the thing it describes.
/// </summary>
[Collection(DatabaseCollection.Name)]
public class ApiBHierarchyDeleteTests
{
    private readonly DatabaseFixture _fx;
    public ApiBHierarchyDeleteTests(DatabaseFixture fx) => _fx = fx;

    private async Task<HttpClient> AdminAsync() => Http(_fx, await UserAsync(_fx, admin: true));

    /// <summary>A project with a build and a finding under it, so a cascade has something to cascade to.</summary>
    private async Task<(Tree Tree, Guid CvId)> PopulatedAsync()
    {
        var tree = await ClientProjectAsync(_fx);
        var cvId = await VersionAsync(_fx, tree.ProjectId, "1.0.0");

        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        db.Findings.Add(NewFinding(cvId, ScannerKind.OpenGrep, Severity.High, "r1"));
        await db.SaveChangesAsync();

        return (tree, cvId);
    }

    private static HttpRequestMessage Delete(string url, string? confirmName)
    {
        var req = new HttpRequestMessage(HttpMethod.Delete, url)
        {
            Content = JsonContent.Create(new { confirmName }),
        };
        return req;
    }

    [SkippableFact]
    public async Task An_admin_deletes_a_project_and_everything_under_it_goes_with_it()
    {
        Skip.IfNot(_fx.Available);
        var admin = await AdminAsync();
        var (tree, cvId) = await PopulatedAsync();

        var response = await admin.SendAsync(
            Delete($"/projects/{tree.ProjectId}", tree.ProjectName));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        // The counts come back rather than a bare 204 — an operator who has just run an
        // irreversible cascade should be told what went.
        var body = await response.Content.ReadFromJsonAsync<Dictionary<string, object>>();
        Assert.Equal("1", body!["builds"].ToString());
        Assert.Equal("1", body["findings"].ToString());

        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        Assert.False(await db.Projects.AnyAsync(p => p.Id == tree.ProjectId));
        Assert.False(await db.ComponentVersions.AnyAsync(v => v.Id == cvId));
        Assert.False(await db.Findings.AnyAsync(f => f.ComponentVersionId == cvId));

        // The client above it is untouched: deleting a project is not deleting a tenant.
        Assert.True(await db.Clients.AnyAsync(c => c.Id == tree.ClientId));
    }

    [SkippableFact]
    public async Task Deleting_a_client_takes_its_projects_with_it()
    {
        Skip.IfNot(_fx.Available);
        var admin = await AdminAsync();
        var (tree, cvId) = await PopulatedAsync();

        var response = await admin.SendAsync(
            Delete($"/clients/{tree.ClientId}", tree.ClientName));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<Dictionary<string, object>>();
        Assert.Equal("1", body!["projects"].ToString());

        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        Assert.False(await db.Clients.AnyAsync(c => c.Id == tree.ClientId));
        Assert.False(await db.Projects.AnyAsync(p => p.Id == tree.ProjectId));
        Assert.False(await db.Findings.AnyAsync(f => f.ComponentVersionId == cvId));
    }

    // ---- the properties that make this safe to expose ------------------------

    [SkippableFact]
    public async Task A_wrong_name_echo_deletes_nothing()
    {
        Skip.IfNot(_fx.Available);

        // The guard is enforced in the service, not only in the dialog: this endpoint is
        // reachable by curl and by anything holding an admin session, and an
        // irreversible cascade deserves the same confirmation whichever door it comes
        // through. A guard that lives in the SPA guards the SPA.
        var admin = await AdminAsync();
        var (tree, _) = await PopulatedAsync();

        foreach (var wrong in new[] { null, "", "   ", "not-the-name", tree.ProjectName.ToUpperInvariant() })
        {
            var response = await admin.SendAsync(Delete($"/projects/{tree.ProjectId}", wrong));

            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Contains(tree.ProjectName, await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        }

        using var scope = _fx.Scope();
        Assert.True(await _fx.Db(scope).Projects.AnyAsync(p => p.Id == tree.ProjectId));
    }

    [SkippableFact]
    public async Task Surrounding_whitespace_is_forgiven_because_a_browser_adds_it()
    {
        Skip.IfNot(_fx.Available);
        var admin = await AdminAsync();
        var (tree, _) = await PopulatedAsync();

        var response = await admin.SendAsync(
            Delete($"/projects/{tree.ProjectId}", $"  {tree.ProjectName}  "));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [SkippableFact]
    public async Task An_architect_who_may_CREATE_a_project_may_not_delete_one()
    {
        Skip.IfNot(_fx.Available);

        // The deliberate authority choice. CreateProject is delegable to a
        // project-scoped role through Capability.CreateProject, and reusing that
        // capability here would let whoever may create a project destroy its entire
        // evidence history. Creating hierarchy and erasing it are not the same
        // authority, so delete is Admin-only for projects as well as clients.
        var (tree, _) = await PopulatedAsync();
        var userId = await UserAsync(_fx, admin: false);
        await GrantAsync(_fx, userId, ProjectRole.Architect, tree.ClientId, null);
        var architect = Http(_fx, userId);

        var response = await architect.SendAsync(
            Delete($"/projects/{tree.ProjectId}", tree.ProjectName));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);

        using var scope = _fx.Scope();
        Assert.True(await _fx.Db(scope).Projects.AnyAsync(p => p.Id == tree.ProjectId));
    }

    [SkippableFact]
    public async Task An_anonymous_caller_cannot_delete_anything()
    {
        Skip.IfNot(_fx.Available);
        var (tree, _) = await PopulatedAsync();

        var response = await Http(_fx, null).SendAsync(
            Delete($"/projects/{tree.ProjectId}", tree.ProjectName));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);

        using var scope = _fx.Scope();
        Assert.True(await _fx.Db(scope).Projects.AnyAsync(p => p.Id == tree.ProjectId));
    }

    [SkippableFact]
    public async Task An_unknown_id_is_a_404_because_it_came_from_the_path()
    {
        Skip.IfNot(_fx.Available);
        var admin = await AdminAsync();

        Assert.Equal(HttpStatusCode.NotFound,
            (await admin.SendAsync(Delete($"/projects/{Guid.NewGuid()}", "anything"))).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound,
            (await admin.SendAsync(Delete($"/clients/{Guid.NewGuid()}", "anything"))).StatusCode);
    }

    [SkippableFact]
    public async Task The_audit_row_outlives_the_thing_it_describes()
    {
        Skip.IfNot(_fx.Available);

        // The reason this route exists at all is that the kubectl delete left no trace.
        // So the audit entry has to survive its own subject — which it does because
        // AuditEntry.ClientId and ProjectId are plain Guids with an index and no foreign
        // key, so nothing cascades them away. If someone ever adds that FK, this fails.
        var admin = await AdminAsync();
        var (tree, _) = await PopulatedAsync();

        await admin.SendAsync(Delete($"/clients/{tree.ClientId}", tree.ClientName));

        using var scope = _fx.Scope();
        var entry = await _fx.Db(scope).AuditEntries
            .SingleAsync(a => a.SubjectId == tree.ClientId && a.Action == "client.deleted");

        // And it says what was destroyed, not just that something was.
        Assert.Contains(tree.ClientName, entry.Detail!, StringComparison.Ordinal);
        Assert.Contains("1 project(s)", entry.Detail!, StringComparison.Ordinal);
        Assert.True(entry.ActorWasAdmin);
    }
}
