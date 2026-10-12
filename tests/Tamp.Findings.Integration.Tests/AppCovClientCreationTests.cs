using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Projects;
using Tamp.Findings.Domain.Values;
using Tamp.Findings.Web.Services;

namespace Tamp.Findings.Integration.Tests;

/// <summary>
/// The client-creation orchestration behind the Portfolio page (TFND-257).
///
/// Extracted from the page's @code block so it can be tested at all: nothing in
/// these suites renders a Blazor component, so logic left in a template is
/// logic nobody exercises. Both of the page's entry points — the toolbar action
/// and the inline affordance in the New-project dialog — run this, so a bug here
/// would be a bug in both.
/// </summary>
[Collection(DatabaseCollection.Name)]
public class AppCovClientCreationTests
{
    private readonly DatabaseFixture _fx;
    public AppCovClientCreationTests(DatabaseFixture fx) => _fx = fx;

    private static Principal Admin() =>
        Principal.For(Guid.NewGuid(), "admin", isAdmin: true, []);

    private static Principal Architect() =>
        Principal.For(Guid.NewGuid(), "architect", isAdmin: false, [ProjectRole.Architect]);

    // ---- MayCreate ----------------------------------------------------------

    [Fact]
    public void Only_an_admin_may_create_a_client()
    {
        // A client sits above every project, so nothing narrower can grant the
        // right to make one — and this has to agree with what
        // HierarchyService.CreateClientAsync actually enforces, or the UI offers
        // a button that always fails.
        Assert.True(ClientCreation.MayCreate(Admin()));
        Assert.False(ClientCreation.MayCreate(Architect()));
        Assert.False(ClientCreation.MayCreate(Principal.For(Guid.NewGuid(), "viewer", false, [])));
    }

    [Fact]
    public void A_signed_out_visitor_may_not_create_a_client()
    {
        // Null is "not signed in", and it must not read as permission.
        Assert.False(ClientCreation.MayCreate(null));
    }

    // ---- CreateAsync --------------------------------------------------------

    [SkippableFact]
    public async Task An_admin_creates_a_client_and_gets_its_id()
    {
        Skip.IfNot(_fx.Available);
        using var scope = _fx.Scope();
        var hierarchy = scope.ServiceProvider.GetRequiredService<HierarchyService>();
        var name = $"cc-{Guid.NewGuid():N}"[..18];

        var (id, error) = await ClientCreation.CreateAsync(Admin(), hierarchy, name);

        Assert.Null(error);
        Assert.NotNull(id);
        Assert.NotEqual(Guid.Empty, id!.Value);
    }

    [SkippableFact]
    public async Task A_signed_out_visitor_is_told_so_rather_than_crashing()
    {
        Skip.IfNot(_fx.Available);
        using var scope = _fx.Scope();
        var hierarchy = scope.ServiceProvider.GetRequiredService<HierarchyService>();

        var (id, error) = await ClientCreation.CreateAsync(null, hierarchy, "whatever");

        Assert.Null(id);
        Assert.Equal("You are not signed in.", error);
    }

    [SkippableFact]
    public async Task A_non_admin_gets_the_services_own_refusal()
    {
        Skip.IfNot(_fx.Available);

        // Not a reworded one. The service's sentences are already written for a
        // reader, and paraphrasing them here would be a second place for the
        // same message to drift.
        using var scope = _fx.Scope();
        var hierarchy = scope.ServiceProvider.GetRequiredService<HierarchyService>();

        var (id, error) = await ClientCreation.CreateAsync(Architect(), hierarchy, "nope");

        Assert.Null(id);
        Assert.Contains("administrator", error!, StringComparison.OrdinalIgnoreCase);
    }

    [SkippableFact]
    public async Task A_blank_name_is_refused_with_a_reason()
    {
        Skip.IfNot(_fx.Available);
        using var scope = _fx.Scope();
        var hierarchy = scope.ServiceProvider.GetRequiredService<HierarchyService>();

        var (id, error) = await ClientCreation.CreateAsync(Admin(), hierarchy, "   ");

        Assert.Null(id);
        Assert.Contains("name", error!, StringComparison.OrdinalIgnoreCase);
    }

    [SkippableFact]
    public async Task A_duplicate_name_is_refused_rather_than_creating_a_second()
    {
        Skip.IfNot(_fx.Available);
        using var scope = _fx.Scope();
        var hierarchy = scope.ServiceProvider.GetRequiredService<HierarchyService>();
        var name = $"dup-{Guid.NewGuid():N}"[..18];

        var first = await ClientCreation.CreateAsync(Admin(), hierarchy, name);
        Assert.NotNull(first.Id);

        var second = await ClientCreation.CreateAsync(Admin(), hierarchy, name);

        Assert.Null(second.Id);
        Assert.Contains("already exists", second.Error!, StringComparison.OrdinalIgnoreCase);
    }

    [SkippableFact]
    public async Task The_name_is_trimmed_so_a_pasted_value_does_not_create_a_near_duplicate()
    {
        Skip.IfNot(_fx.Available);
        using var scope = _fx.Scope();
        var hierarchy = scope.ServiceProvider.GetRequiredService<HierarchyService>();
        var name = $"trim-{Guid.NewGuid():N}"[..18];

        var created = await ClientCreation.CreateAsync(Admin(), hierarchy, $"  {name}  ");
        Assert.NotNull(created.Id);

        // The untrimmed form must now collide, not sit alongside it.
        var again = await ClientCreation.CreateAsync(Admin(), hierarchy, name);
        Assert.Null(again.Id);
    }
}
