using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Poam;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Integration.Tests;

/// <summary>
/// The structured 800-53 control field on a POA&amp;M item (TFND-180 increment 4).
///
/// SourceRef already existed and is free-form, interpreted per SourceKind — so it
/// cannot answer "which controls does this weakness affect", which is the column the
/// federal POA&amp;M template puts beside the weakness. ControlIds is that column, and
/// the whole value of making it structured rather than another free string is that the
/// stored value resolves to a real control. These tests are about that promise:
/// normalised on write, and refused when it does not resolve.
///
/// They run against the catalog the host seeds at startup, which is the shipped NIST
/// 800-53 Rev 5 OSCAL catalog — so the ids used here are real ones.
/// </summary>
[Collection(DatabaseCollection.Name)]
public class AppCovPoamControlIdTests
{
    private readonly DatabaseFixture _fx;
    public AppCovPoamControlIdTests(DatabaseFixture fx) => _fx = fx;

    private static PoamDraft Draft(IReadOnlyList<string>? controls = null) =>
        new("weak", "desc", null, null, null, Severity.High, PoamStatus.Open, null, [], controls);

    [SkippableFact]
    public async Task Control_ids_are_normalised_to_the_catalogs_own_form()
    {
        Skip.IfNot(_fx.Available);
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var actors = await AppCovSeed.UsersAsync(db);
        var (client, project) = await AppCovSeed.ClientProjectAsync(db, "poamctl-norm");
        var target = ScopeTarget.Project(client.Id, project.Id);
        var svc = scope.ServiceProvider.GetRequiredService<PoamService>();

        // Three spellings of two controls. "cm-6.1" is OSCAL's enhancement form and
        // "CM-6(1)" is the catalog's display form for the same control; storing both
        // would show a reader two controls where there is one.
        var created = await svc.CreateAsync(
            actors.Lead, target, project.Id, Draft(["cm-6", " CM-6 ", "cm-6.1"]));
        Assert.True(created.Success, created.Error);

        var item = await db.PoamItems.AsNoTracking().SingleAsync(p => p.Id == created.Value);
        Assert.Equal(["CM-6", "CM-6(1)"], item.ControlIds);
    }

    [SkippableFact]
    public async Task A_control_that_is_not_in_the_catalog_is_refused_and_named()
    {
        Skip.IfNot(_fx.Available);
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var actors = await AppCovSeed.UsersAsync(db);
        var (client, project) = await AppCovSeed.ClientProjectAsync(db, "poamctl-bad");
        var target = ScopeTarget.Project(client.Id, project.Id);
        var svc = scope.ServiceProvider.GetRequiredService<PoamService>();

        // The point of the structured field. An id that resolves to nothing would be
        // printed to an Authorizing Official as the control they are being asked about.
        var result = await svc.CreateAsync(actors.Lead, target, project.Id, Draft(["CM-6", "ZZ-99"]));

        Assert.False(result.Success);
        Assert.False(result.WasDenied);
        Assert.Contains("ZZ-99", result.Error!, StringComparison.Ordinal);

        // And nothing was written — a partial accept would store half a mapping.
        Assert.False(await db.PoamItems.AnyAsync(p => p.ProjectId == project.Id));
    }

    [SkippableFact]
    public async Task No_control_mapping_is_an_ordinary_state()
    {
        Skip.IfNot(_fx.Available);
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var actors = await AppCovSeed.UsersAsync(db);
        var (client, project) = await AppCovSeed.ClientProjectAsync(db, "poamctl-none");
        var target = ScopeTarget.Project(client.Id, project.Id);
        var svc = scope.ServiceProvider.GetRequiredService<PoamService>();

        // A scanner finding may have no control mapped yet, and refusing the record
        // until someone maps one would push the record out of the product.
        var created = await svc.CreateAsync(actors.Lead, target, project.Id, Draft(null));
        Assert.True(created.Success, created.Error);

        var item = await db.PoamItems.AsNoTracking().SingleAsync(p => p.Id == created.Value);
        Assert.Empty(item.ControlIds);
    }

    [SkippableFact]
    public async Task An_edit_can_add_and_clear_the_mapping()
    {
        Skip.IfNot(_fx.Available);
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var actors = await AppCovSeed.UsersAsync(db);
        var (client, project) = await AppCovSeed.ClientProjectAsync(db, "poamctl-edit");
        var target = ScopeTarget.Project(client.Id, project.Id);
        var svc = scope.ServiceProvider.GetRequiredService<PoamService>();

        var created = await svc.CreateAsync(actors.Lead, target, project.Id, Draft());
        var id = created.Value;

        Assert.True((await svc.UpdateAsync(
            actors.Lead, target, project.Id, id, Draft(["sc-7"]))).Success);
        using (var read = _fx.Scope())
            Assert.Equal(["SC-7"], (await _fx.Db(read).PoamItems.SingleAsync(p => p.Id == id)).ControlIds);

        // An explicit empty list clears it. A mapping someone decided was wrong has to
        // be removable, or the only fix is deleting the item and losing its history.
        Assert.True((await svc.UpdateAsync(
            actors.Lead, target, project.Id, id, Draft([]))).Success);
        using (var read = _fx.Scope())
            Assert.Empty((await _fx.Db(read).PoamItems.SingleAsync(p => p.Id == id)).ControlIds);
    }

    [SkippableFact]
    public async Task The_board_and_the_record_both_carry_the_mapping()
    {
        Skip.IfNot(_fx.Available);
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var actors = await AppCovSeed.UsersAsync(db);
        var (client, project) = await AppCovSeed.ClientProjectAsync(db, "poamctl-read");
        var target = ScopeTarget.Project(client.Id, project.Id);
        var svc = scope.ServiceProvider.GetRequiredService<PoamService>();
        var query = scope.ServiceProvider.GetRequiredService<PoamQuery>();

        var created = await svc.CreateAsync(actors.Lead, target, project.Id, Draft(["au-2", "sc-7"]));

        // On the board as well as the record: an AO scanning the list is asking which
        // controls have slipped, and making them open every item to find out defeats it.
        var board = await query.BoardAsync(project.Id, DateTimeOffset.UtcNow);
        Assert.Equal(["AU-2", "SC-7"], board.Items.Single().ControlIds);

        var record = await query.RecordAsync(project.Id, created.Value, DateTimeOffset.UtcNow);
        Assert.Equal(["AU-2", "SC-7"], record!.ControlIds);
    }
}
