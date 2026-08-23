using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Poam;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Integration.Tests;

// POA&M (TFND-95 … TFND-98).
//
// The audit trail IS the deliverable an Authorizing Official reads, so the
// assertions here are as much about what gets WRITTEN as about what comes back:
// an unaudited transition is not a missing log line, it is a gap in the federal
// record.
[Collection(DatabaseCollection.Name)]
public class PoamIntegrationTests
{
    private readonly DatabaseFixture _fx;

    public PoamIntegrationTests(DatabaseFixture fx) => _fx = fx;

    // ---- Past due -----------------------------------------------------------

    [SkippableFact]
    public async Task An_overdue_open_item_is_past_due()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var query = scope.ServiceProvider.GetRequiredService<PoamQuery>();

        var board = await query.BoardAsync(world.ProjectId, world.AsOf);

        Assert.Equal(1, board.Stats.PastDue);
        // And it sorts first: an AO opening this page is asking what slipped.
        Assert.True(board.Items[0].PastDue);
    }

    [SkippableFact]
    public async Task An_unscheduled_item_is_never_past_due_but_is_counted_separately()
    {
        Skip.IfNot(_fx.Available);

        // The gate's own blind spot. The screen must show the same number the
        // gate does — and surface the hole rather than hide it.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var query = scope.ServiceProvider.GetRequiredService<PoamQuery>();

        var board = await query.BoardAsync(world.ProjectId, world.AsOf);
        var unscheduled = board.Items.Single(i => i.Title == "Unscheduled weakness");

        Assert.False(unscheduled.PastDue);
        Assert.True(board.Stats.Unscheduled >= 1);
    }

    [SkippableFact]
    public async Task A_closed_item_past_its_date_is_not_past_due()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var query = scope.ServiceProvider.GetRequiredService<PoamQuery>();

        var board = await query.BoardAsync(world.ProjectId, world.AsOf);
        var closed = board.Items.Single(i => i.Title == "Closed late");

        // The date passed, but the work is done. Counting it would inflate the
        // gate with items nobody can act on.
        Assert.False(closed.PastDue);
    }

    // ---- Authorization ------------------------------------------------------

    [SkippableFact]
    public async Task An_admin_cannot_accept_risk()
    {
        Skip.IfNot(_fx.Available);

        // The matrix deliberately withholds AcceptRisk from Admin: it is an
        // Authorizing Official decision, not a systems privilege. This is the
        // test that stops someone "fixing" the matrix.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var service = scope.ServiceProvider.GetRequiredService<PoamService>();

        var result = await service.TransitionAsync(
            world.Admin, world.Scope, world.ProjectId, world.OverdueId, PoamStatus.RiskAccepted);

        Assert.False(result.Success);
        Assert.True(result.WasDenied);
    }

    [SkippableFact]
    public async Task An_admin_can_complete_an_item()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var service = scope.ServiceProvider.GetRequiredService<PoamService>();

        var result = await service.TransitionAsync(
            world.Admin, world.Scope, world.ProjectId, world.OverdueId, PoamStatus.Completed);

        Assert.True(result.Success);
    }

    [SkippableFact]
    public async Task A_viewer_cannot_create_an_item()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var service = scope.ServiceProvider.GetRequiredService<PoamService>();

        var result = await service.CreateAsync(
            world.Viewer, world.Scope, world.ProjectId, Draft("Something"));

        Assert.True(result.WasDenied);
    }

    // ---- Stamps -------------------------------------------------------------

    [SkippableFact]
    public async Task Completing_stamps_both_closed_and_completed()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var service = scope.ServiceProvider.GetRequiredService<PoamService>();
        var query = scope.ServiceProvider.GetRequiredService<PoamQuery>();

        await service.TransitionAsync(
            world.Admin, world.Scope, world.ProjectId, world.OverdueId, PoamStatus.Completed);

        var record = await query.RecordAsync(world.ProjectId, world.OverdueId, world.AsOf);

        Assert.NotNull(record!.ClosedAt);
        Assert.NotNull(record.ActualCompletionDate);
    }

    [SkippableFact]
    public async Task Cancelling_closes_the_item_without_claiming_it_was_completed()
    {
        Skip.IfNot(_fx.Available);

        // ActualCompletionDate means the weakness was remediated. An AO reading
        // a completion date is entitled to read it as work done, so cancelling
        // and accepting risk must never stamp it.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var service = scope.ServiceProvider.GetRequiredService<PoamService>();
        var query = scope.ServiceProvider.GetRequiredService<PoamQuery>();

        await service.TransitionAsync(
            world.Admin, world.Scope, world.ProjectId, world.OverdueId, PoamStatus.Cancelled);

        var record = await query.RecordAsync(world.ProjectId, world.OverdueId, world.AsOf);

        Assert.NotNull(record!.ClosedAt);
        Assert.Null(record.ActualCompletionDate);
    }

    // ---- Audit --------------------------------------------------------------

    [SkippableFact]
    public async Task Risk_acceptance_is_audited_as_a_risk_class_event()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var service = scope.ServiceProvider.GetRequiredService<PoamService>();
        var db = _fx.Db(scope);

        await service.TransitionAsync(
            world.InfoSec, world.Scope, world.ProjectId, world.OverdueId, PoamStatus.RiskAccepted);

        var entry = db.AuditEntries
            .Where(a => a.SubjectId == world.OverdueId)
            .OrderByDescending(a => a.At)
            .First();

        // "Risk acceptance, role grants and key changes are what an assessor
        // reads first" — which is why it is a class, not a search term.
        Assert.Equal(AuditClass.Risk, entry.Class);
        Assert.Contains("risk_accepted", entry.Action, StringComparison.Ordinal);
    }

    [SkippableFact]
    public async Task An_extension_records_its_reason_verbatim()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var service = scope.ServiceProvider.GetRequiredService<PoamService>();
        var db = _fx.Db(scope);

        await service.RequestExtensionAsync(
            world.Admin, world.Scope, world.ProjectId, world.OverdueId,
            world.AsOf.AddDays(30), "AO granted 30 days pending vendor patch");

        var entry = db.AuditEntries
            .Where(a => a.SubjectId == world.OverdueId)
            .OrderByDescending(a => a.At)
            .First();

        Assert.Contains("vendor patch", entry.Detail!, StringComparison.Ordinal);
    }

    [SkippableFact]
    public async Task An_extension_with_no_reason_is_refused()
    {
        Skip.IfNot(_fx.Available);

        // Without a reason, an extension is indistinguishable from someone
        // quietly making a past-due item stop being past due.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var service = scope.ServiceProvider.GetRequiredService<PoamService>();

        var result = await service.RequestExtensionAsync(
            world.Admin, world.Scope, world.ProjectId, world.OverdueId, world.AsOf.AddDays(30), "   ");

        Assert.False(result.Success);
        Assert.False(result.WasDenied);
    }

    [SkippableFact]
    public async Task Deleting_leaves_an_audit_entry_naming_what_was_deleted()
    {
        Skip.IfNot(_fx.Available);

        // The row is gone; the record that it existed must not be.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var service = scope.ServiceProvider.GetRequiredService<PoamService>();
        var db = _fx.Db(scope);

        await service.DeleteAsync(world.Admin, world.Scope, world.ProjectId, world.OverdueId);

        var entry = db.AuditEntries
            .Where(a => a.SubjectId == world.OverdueId)
            .OrderByDescending(a => a.At)
            .First();

        Assert.Equal("poam.deleted", entry.Action);
        Assert.Contains("Overdue weakness", entry.Detail!, StringComparison.Ordinal);
    }

    // ---- Validation ---------------------------------------------------------

    [SkippableFact]
    public async Task An_item_with_no_weakness_description_is_refused()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var service = scope.ServiceProvider.GetRequiredService<PoamService>();

        var result = await service.CreateAsync(
            world.Admin, world.Scope, world.ProjectId,
            Draft("Titled but empty") with { WeaknessDescription = "  " });

        Assert.False(result.Success);
        Assert.False(result.WasDenied);
    }

    [SkippableFact]
    public async Task The_edit_dialog_cannot_change_status()
    {
        Skip.IfNot(_fx.Available);

        // Status moves through TransitionAsync, which enforces the two
        // capabilities the matrix separates. Letting an edit write it directly
        // would route around both — including AcceptRisk.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var service = scope.ServiceProvider.GetRequiredService<PoamService>();

        var result = await service.UpdateAsync(
            world.Admin, world.Scope, world.ProjectId, world.OverdueId,
            Draft("Overdue weakness") with { Status = PoamStatus.RiskAccepted });

        Assert.False(result.Success);
        Assert.False(result.WasDenied);
    }

    // ---- Linked findings ----------------------------------------------------

    [SkippableFact]
    public async Task Linked_findings_resolve_on_the_record()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var query = scope.ServiceProvider.GetRequiredService<PoamQuery>();

        var record = await query.RecordAsync(world.ProjectId, world.LinkedId, world.AsOf);

        Assert.Single(record!.LinkedFindings);
        Assert.Equal("src/Api/Program.cs", record.LinkedFindings[0].FilePath);
    }

    [SkippableFact]
    public async Task A_link_that_no_longer_resolves_is_counted_rather_than_dropped()
    {
        Skip.IfNot(_fx.Available);

        // Silently dropping it would let a POA&M cite evidence that has since
        // been deleted and still look complete to an auditor.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var query = scope.ServiceProvider.GetRequiredService<PoamQuery>();

        var record = await query.RecordAsync(world.ProjectId, world.LinkedId, world.AsOf);

        Assert.Equal(1, record!.UnresolvedLinkCount);
    }

    // ---- Seed ---------------------------------------------------------------

    private static PoamDraft Draft(string title) => new(
        title, "A weakness worth writing down.", null, null, null,
        Severity.High, PoamStatus.Open, null, []);

    private sealed record World(
        Guid ProjectId, ScopeTarget Scope, DateTimeOffset AsOf,
        Guid OverdueId, Guid LinkedId,
        Principal Admin, Principal InfoSec, Principal Viewer);

    private async Task<World> SeedAsync()
    {
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);

        var suffix = Guid.NewGuid().ToString("N")[..8];
        var client = new Client { Name = $"poam-client-{suffix}" };
        var project = new Project { ClientId = client.Id, Name = $"poam-project-{suffix}" };
        var component = new Component { ProjectId = project.Id, Name = $"poam-component-{suffix}" };
        var version = new ComponentVersion
        {
            ComponentId = component.Id, VersionString = "0.1.0", CommitSha = suffix + "cccccc",
        };

        db.Clients.Add(client);
        db.Projects.Add(project);
        db.Components.Add(component);
        db.ComponentVersions.Add(version);

        var author = new User
        {
            Login = $"poam-{suffix}",
            DisplayName = "Poam Author",
            Email = $"poam-{suffix}@example.test",
            IsApproved = true,
        };
        db.Users.Add(author);

        var finding = new Finding
        {
            ComponentVersionId = version.Id,
            Hash = Guid.NewGuid().ToString("N"),
            Scanner = ScannerKind.Roslyn,
            RuleId = "RULE-POAM",
            Severity = Severity.High,
            Title = "Something the POA&M cites",
            FilePath = "src/Api/Program.cs",
            Status = FindingStatus.Open,
        };
        db.Findings.Add(finding);

        var asOf = new DateTimeOffset(2026, 6, 1, 0, 0, 0, TimeSpan.Zero);

        PoamItem Item(string title, PoamStatus status, DateTimeOffset? due,
                      DateTimeOffset? closed = null, List<Guid>? links = null)
        {
            var item = new PoamItem
            {
                ProjectId = project.Id,
                Title = title,
                WeaknessDescription = $"{title} — described for the AO.",
                Severity = Severity.High,
                Status = status,
                ScheduledCompletionDate = due,
                ClosedAt = closed,
                LinkedFindingIds = links ?? [],
                AuthorUserId = author.Id,
            };
            db.PoamItems.Add(item);
            return item;
        }

        var overdue = Item("Overdue weakness", PoamStatus.Open, asOf.AddDays(-10));
        Item("Unscheduled weakness", PoamStatus.InProgress, null);
        Item("Closed late", PoamStatus.Completed, asOf.AddDays(-20), closed: asOf.AddDays(-5));
        // One link that resolves and one that never will.
        var linked = Item("Linked weakness", PoamStatus.Open, asOf.AddDays(30),
                          links: [finding.Id, Guid.NewGuid()]);

        await db.SaveChangesAsync();

        var target = ScopeTarget.Project(client.Id, project.Id);
        return new World(
            project.Id, target, asOf, overdue.Id, linked.Id,
            Admin: Principal.For(author.Id, author.Login, isAdmin: true, []),
            InfoSec: Principal.For(author.Id, author.Login, isAdmin: false, [ProjectRole.InfoSecOfficer]),
            Viewer: Principal.For(author.Id, author.Login, isAdmin: false, []));
    }
}
