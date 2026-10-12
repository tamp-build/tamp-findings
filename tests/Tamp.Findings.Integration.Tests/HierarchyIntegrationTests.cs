using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Projects;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Integration.Tests;

// Creating clients and projects (TFND-85) — the flow the hand-off renders
// buttons for and then lists as not covered.
[Collection(DatabaseCollection.Name)]
public class HierarchyIntegrationTests
{
    private readonly DatabaseFixture _fx;

    public HierarchyIntegrationTests(DatabaseFixture fx) => _fx = fx;

    private static Principal Admin() => Principal.For(Guid.NewGuid(), "admin", isAdmin: true, []);
    private static Principal Architect() =>
        Principal.For(Guid.NewGuid(), "architect", isAdmin: false, [ProjectRole.Architect]);

    [SkippableFact]
    public async Task An_admin_can_create_a_client_and_a_project_beneath_it()
    {
        Skip.IfNot(_fx.Available);

        using var scope = _fx.Scope();
        var hierarchy = scope.ServiceProvider.GetRequiredService<HierarchyService>();
        var name = $"client-{Guid.NewGuid():N}"[..20];

        var client = await hierarchy.CreateClientAsync(Admin(), name);
        Assert.True(client.Success);

        var project = await hierarchy.CreateProjectAsync(Admin(), client.Value, "tamp", null);
        Assert.True(project.Success);
    }

    [SkippableFact]
    public async Task Creating_a_client_is_admin_only()
    {
        Skip.IfNot(_fx.Available);

        // A client is the top of the hierarchy and every scope beneath it
        // inherits from it, so it is closer to an instance operation than a
        // project one.
        using var scope = _fx.Scope();
        var hierarchy = scope.ServiceProvider.GetRequiredService<HierarchyService>();

        var result = await hierarchy.CreateClientAsync(Architect(), "should-not-exist");

        Assert.False(result.Success);
        Assert.True(result.WasDenied);
    }

[SkippableFact]
    public async Task Creating_a_client_is_audited()
    {
        Skip.IfNot(_fx.Available);

        // TFND-258. Creating a tenant is the structural change an assessor looks
        // for in the log, and the HTTP path used to add the row itself and
        // record nothing — so the same act left a trace through the UI and none
        // over the API. Both go through this service now, which is where the
        // audit row is written.
        using var scope = _fx.Scope();
        var hierarchy = scope.ServiceProvider.GetRequiredService<HierarchyService>();
        var db = _fx.Db(scope);
        var name = $"audited-{Guid.NewGuid():N}"[..20];

        var client = await hierarchy.CreateClientAsync(Admin(), name);
        Assert.True(client.Success);

        var entry = await db.AuditEntries
            .Where(a => a.SubjectId == client.Value)
            .SingleAsync();

        Assert.Equal("client.created", entry.Action);
        Assert.Contains(name, entry.Detail!, StringComparison.Ordinal);
    }

    [SkippableFact]
    public async Task Creating_a_project_is_audited()
    {
        Skip.IfNot(_fx.Available);

        using var scope = _fx.Scope();
        var hierarchy = scope.ServiceProvider.GetRequiredService<HierarchyService>();
        var db = _fx.Db(scope);

        var client = await hierarchy.CreateClientAsync(Admin(), $"c-{Guid.NewGuid():N}"[..18]);
        var project = await hierarchy.CreateProjectAsync(Admin(), client.Value, "audited-proj", null);
        Assert.True(project.Success);

        var entry = await db.AuditEntries
            .Where(a => a.SubjectId == project.Value)
            .SingleAsync();

        Assert.Equal("project.created", entry.Action);
        Assert.Contains("audited-proj", entry.Detail!, StringComparison.Ordinal);
    }

    [SkippableFact]
    public async Task An_architect_can_create_a_project_without_being_an_admin()
    {
        Skip.IfNot(_fx.Available);

        // The authorization discrepancy half of TFND-258. CreateProject is held
        // by Admin AND Architect, and the Blazor path always honoured that — the
        // HTTP endpoint demanded IsAdmin, so an Architect could create a project
        // in the app and not over the API, for no reason anybody chose. Both
        // paths now ask this service, so this is the rule in one place.
        using var scope = _fx.Scope();
        var hierarchy = scope.ServiceProvider.GetRequiredService<HierarchyService>();

        var client = await hierarchy.CreateClientAsync(Admin(), $"arch-{Guid.NewGuid():N}"[..18]);
        var project = await hierarchy.CreateProjectAsync(Architect(), client.Value, "by-architect", null);

        Assert.True(project.Success);
    }

    [SkippableFact]
    public async Task Project_names_are_unique_per_client_not_globally()
    {
        Skip.IfNot(_fx.Available);

        // The URL scheme is /c/{client}/p/{project}, so two clients may each
        // have a "tamp" without ambiguity. Forbidding that would be an
        // arbitrary restriction on a multi-tenant install.
        using var scope = _fx.Scope();
        var hierarchy = scope.ServiceProvider.GetRequiredService<HierarchyService>();

        var a = await hierarchy.CreateClientAsync(Admin(), $"a-{Guid.NewGuid():N}"[..16]);
        var b = await hierarchy.CreateClientAsync(Admin(), $"b-{Guid.NewGuid():N}"[..16]);

        Assert.True((await hierarchy.CreateProjectAsync(Admin(), a.Value, "tamp", null)).Success);
        Assert.True((await hierarchy.CreateProjectAsync(Admin(), b.Value, "tamp", null)).Success);

        // But not twice under the same client.
        var duplicate = await hierarchy.CreateProjectAsync(Admin(), a.Value, "tamp", null);
        Assert.False(duplicate.Success);
        Assert.False(duplicate.WasDenied);
    }

    [SkippableFact]
    public async Task Creating_a_project_writes_an_audit_entry_in_the_same_transaction()
    {
        Skip.IfNot(_fx.Available);

        using var scope = _fx.Scope();
        var hierarchy = scope.ServiceProvider.GetRequiredService<HierarchyService>();
        var db = _fx.Db(scope);

        var client = await hierarchy.CreateClientAsync(Admin(), $"aud-{Guid.NewGuid():N}"[..16]);
        var project = await hierarchy.CreateProjectAsync(Admin(), client.Value, "audited", null);

        var entry = db.AuditEntries.FirstOrDefault(e => e.SubjectId == project.Value);

        Assert.NotNull(entry);
        Assert.Equal("project.created", entry!.Action);
    }
}
