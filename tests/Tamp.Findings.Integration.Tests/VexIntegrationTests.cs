using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Vex;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Integration.Tests;

// VEX statements (TFND-99).
//
// A VEX statement is the official answer to "why didn't you patch this CVE?".
// The bar these tests hold: a statement that does not actually relieve the CVE
// must never look like one that does, at any layer.
[Collection(DatabaseCollection.Name)]
public class VexIntegrationTests
{
    private readonly DatabaseFixture _fx;

    public VexIntegrationTests(DatabaseFixture fx) => _fx = fx;

    [SkippableFact]
    public async Task A_justified_not_affected_relieves_the_cve()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var vex = scope.ServiceProvider.GetRequiredService<VexQuery>();

        await vex.SaveAsync(world.InfoSec, world.Scope, world.ProjectId, null, new VexDraft(
            "CVE-2024-11111", "pkg:nuget/Log4Net", null,
            VexStatementStatus.NotAffected, VexJustification.VulnerableCodeNotInExecutePath,
            "We never deserialize untrusted input.", null));

        var rows = await vex.ListAsync(world.ProjectId);

        Assert.True(rows.Single().Suppresses);
    }

    [SkippableFact]
    public async Task A_not_affected_with_no_justification_is_refused_at_authoring_time()
    {
        Skip.IfNot(_fx.Available);

        // Enforced here as well as in VexResolver so the author is told at the
        // point of writing, rather than discovering later that their statement
        // counted for nothing.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var vex = scope.ServiceProvider.GetRequiredService<VexQuery>();

        var result = await vex.SaveAsync(world.InfoSec, world.Scope, world.ProjectId, null, new VexDraft(
            "CVE-2024-11111", "pkg:nuget/Log4Net", null,
            VexStatementStatus.NotAffected, null, null, null));

        Assert.False(result.Success);
        Assert.False(result.WasDenied);
        Assert.Contains("justification", result.Error!, StringComparison.OrdinalIgnoreCase);
    }

    [SkippableFact]
    public async Task An_under_investigation_statement_does_not_relieve_anything()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var vex = scope.ServiceProvider.GetRequiredService<VexQuery>();

        await vex.SaveAsync(world.LeadDev, world.Scope, world.ProjectId, null, new VexDraft(
            "CVE-2024-22222", "pkg:npm/lodash", null,
            VexStatementStatus.UnderInvestigation, null, "Triage in progress.", null));

        Assert.False((await vex.ListAsync(world.ProjectId)).Single().Suppresses);
    }

    [SkippableFact]
    public async Task Unfinished_statements_sort_ahead_of_settled_ones()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var vex = scope.ServiceProvider.GetRequiredService<VexQuery>();

        await vex.SaveAsync(world.InfoSec, world.Scope, world.ProjectId, null, new VexDraft(
            "CVE-2024-00001", "pkg:nuget/Settled", null,
            VexStatementStatus.Fixed, null, null, null));
        await vex.SaveAsync(world.InfoSec, world.Scope, world.ProjectId, null, new VexDraft(
            "CVE-2024-00002", "pkg:nuget/Open", null,
            VexStatementStatus.UnderInvestigation, null, null, null));

        var rows = await vex.ListAsync(world.ProjectId);

        // The ones still asking a question come first, even though the settled
        // one sorts earlier by advisory id.
        Assert.False(rows[0].Suppresses);
    }

    // ---- Authorization ------------------------------------------------------

    [SkippableFact]
    public async Task A_lead_dev_may_draft_but_not_publish_a_relieving_statement()
    {
        Skip.IfNot(_fx.Available);

        // Lead Dev drafts, InfoSec publishes. The split only means anything if
        // writing a SUPPRESSING status is what needs the publish capability.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var vex = scope.ServiceProvider.GetRequiredService<VexQuery>();

        var draft = await vex.SaveAsync(world.LeadDev, world.Scope, world.ProjectId, null, new VexDraft(
            "CVE-2024-33333", "pkg:nuget/Thing", null,
            VexStatementStatus.UnderInvestigation, null, null, null));
        Assert.True(draft.Success);

        var publish = await vex.SaveAsync(world.LeadDev, world.Scope, world.ProjectId, null, new VexDraft(
            "CVE-2024-44444", "pkg:nuget/Thing", null,
            VexStatementStatus.Fixed, null, null, null));

        Assert.True(publish.WasDenied);
    }

    [SkippableFact]
    public async Task A_viewer_may_not_author_at_all()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var vex = scope.ServiceProvider.GetRequiredService<VexQuery>();

        var result = await vex.SaveAsync(world.Viewer, world.Scope, world.ProjectId, null, new VexDraft(
            "CVE-2024-55555", "pkg:nuget/Thing", null,
            VexStatementStatus.UnderInvestigation, null, null, null));

        Assert.True(result.WasDenied);
    }

    // ---- Duplicates and retirement -----------------------------------------

    [SkippableFact]
    public async Task A_second_active_statement_for_the_same_cve_is_refused()
    {
        Skip.IfNot(_fx.Available);

        // Two answers of record and no way to tell which one scoring used.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var vex = scope.ServiceProvider.GetRequiredService<VexQuery>();

        var draft = new VexDraft(
            "CVE-2024-66666", "pkg:nuget/Dup", null,
            VexStatementStatus.UnderInvestigation, null, null, null);

        Assert.True((await vex.SaveAsync(world.InfoSec, world.Scope, world.ProjectId, null, draft)).Success);

        var second = await vex.SaveAsync(world.InfoSec, world.Scope, world.ProjectId, null, draft);

        Assert.False(second.Success);
        Assert.False(second.WasDenied);
    }

    [SkippableFact]
    public async Task Retiring_hides_the_statement_without_deleting_it()
    {
        Skip.IfNot(_fx.Available);

        // "Why did this CVE stop counting in May?" is a question someone asks
        // years later, and a deleted row cannot answer it.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var vex = scope.ServiceProvider.GetRequiredService<VexQuery>();

        var created = await vex.SaveAsync(world.InfoSec, world.Scope, world.ProjectId, null, new VexDraft(
            "CVE-2024-77777", "pkg:nuget/Retire", null,
            VexStatementStatus.Fixed, null, null, null));

        await vex.RetireAsync(world.InfoSec, world.Scope, world.ProjectId, created.Value);

        Assert.Empty(await vex.ListAsync(world.ProjectId));
        Assert.Single(await vex.ListAsync(world.ProjectId, includeRetired: true));
    }

    [SkippableFact]
    public async Task Retiring_after_the_first_time_is_a_no_op_rather_than_a_second_audit_entry()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var vex = scope.ServiceProvider.GetRequiredService<VexQuery>();

        var created = await vex.SaveAsync(world.InfoSec, world.Scope, world.ProjectId, null, new VexDraft(
            "CVE-2024-88888", "pkg:nuget/Twice", null,
            VexStatementStatus.Fixed, null, null, null));

        await vex.RetireAsync(world.InfoSec, world.Scope, world.ProjectId, created.Value);
        var again = await vex.RetireAsync(world.InfoSec, world.Scope, world.ProjectId, created.Value);

        Assert.True(again.Success);
        Assert.False(again.Value);
    }

    // ---- Audit --------------------------------------------------------------

    [SkippableFact]
    public async Task Publishing_a_relieving_statement_is_audited_as_a_risk_decision()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var vex = scope.ServiceProvider.GetRequiredService<VexQuery>();
        var db = _fx.Db(scope);

        var created = await vex.SaveAsync(world.InfoSec, world.Scope, world.ProjectId, null, new VexDraft(
            "CVE-2024-99999", "pkg:nuget/Audited", null,
            VexStatementStatus.NotAffected, VexJustification.ComponentNotPresent, null, null));

        var entry = db.AuditEntries.Single(a => a.SubjectId == created.Value);

        Assert.Equal(AuditClass.Risk, entry.Class);
        Assert.Equal("vex.published", entry.Action);
    }

    [SkippableFact]
    public async Task A_draft_is_not_audited_as_a_risk_decision()
    {
        Skip.IfNot(_fx.Available);

        // Work in progress is not a change to the risk picture, and classing it
        // as one would bury the real decisions an assessor reads first.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var vex = scope.ServiceProvider.GetRequiredService<VexQuery>();
        var db = _fx.Db(scope);

        var created = await vex.SaveAsync(world.LeadDev, world.Scope, world.ProjectId, null, new VexDraft(
            "CVE-2024-10101", "pkg:nuget/Drafted", null,
            VexStatementStatus.UnderInvestigation, null, null, null));

        var entry = db.AuditEntries.Single(a => a.SubjectId == created.Value);

        Assert.NotEqual(AuditClass.Risk, entry.Class);
    }

    // ---- Seed ---------------------------------------------------------------

    private sealed record World(
        Guid ProjectId, ScopeTarget Scope,
        Principal InfoSec, Principal LeadDev, Principal Viewer);

    private async Task<World> SeedAsync()
    {
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);

        var suffix = Guid.NewGuid().ToString("N")[..8];
        var client = new Client { Name = $"vex-client-{suffix}" };
        var project = new Project { ClientId = client.Id, Name = $"vex-project-{suffix}" };
        var author = new User
        {
            Login = $"vex-{suffix}",
            DisplayName = "Vex Author",
            Email = $"vex-{suffix}@example.test",
            IsApproved = true,
        };

        db.Clients.Add(client);
        db.Projects.Add(project);
        db.Users.Add(author);
        await db.SaveChangesAsync();

        var target = ScopeTarget.Project(client.Id, project.Id);
        return new World(
            project.Id, target,
            InfoSec: Principal.For(author.Id, author.Login, isAdmin: false, [ProjectRole.InfoSecOfficer]),
            LeadDev: Principal.For(author.Id, author.Login, isAdmin: false, [ProjectRole.LeadDev]),
            Viewer: Principal.For(author.Id, author.Login, isAdmin: false, []));
    }
}
