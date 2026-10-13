using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Approvals;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Risk;
using Tamp.Findings.Application.Vex;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Integration.Tests;

/// <summary>
/// A staleness exemption needs a reviewer before it stops costing anything (TFND-225).
///
/// v1 (TFND-226) wrote the VEX statement immediately and the component stopped counting
/// on one person's say-so. These tests are about the property that replaced it, and the
/// first one is the ticket's actual requirement: a filed exemption changes NOTHING about
/// the score until somebody else agrees.
/// </summary>
[Collection(DatabaseCollection.Name)]
public class StalenessExemptionApprovalTests
{
    private readonly DatabaseFixture _fx;
    public StalenessExemptionApprovalTests(DatabaseFixture fx) => _fx = fx;

    private sealed record World(Guid ClientId, Guid ProjectId, string BarePurl, string Version, string Purl);

    private async Task<World> SeedAsync()
    {
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var s = Guid.NewGuid().ToString("N")[..8];

        var client = new Client { Name = $"sx-client-{s}" };
        var project = new Project { ClientId = client.Id, Name = $"sx-project-{s}" };
        var version = new ComponentVersion { ProjectId = project.Id, VersionString = "1.0.0", CommitSha = $"{s}sx" };
        var snap = new SbomSnapshot { ComponentVersionId = version.Id, ToolName = "syft", SpecVersion = "1.5" };
        db.Clients.Add(client);
        db.Projects.Add(project);
        db.ComponentVersions.Add(version);
        db.SbomSnapshots.Add(snap);

        var bare = $"pkg:nuget/Platforms.{s}";
        db.SbomComponents.Add(new SbomComponent
        {
            SbomSnapshotId = snap.Id, Purl = $"{bare}@1.1.0", Name = $"Platforms.{s}", Version = "1.1.0",
            LatestVersion = "7.0.0", LatestReleasedAt = DateTimeOffset.UtcNow.AddDays(-400),
        });

        await db.SaveChangesAsync();
        return new World(client.Id, project.Id, bare, "1.1.0", $"{bare}@1.1.0");
    }

    private static string Payload(World w) => JsonSerializer.Serialize(new VexDraft(
        VexStatement.StalenessAdvisoryId, w.BarePurl, w.Version,
        VexStatementStatus.NotAffected, VexJustification.BuildTimeOnly,
        "Analyzer only; never shipped.", null));

    /// <summary>File the request the way the page does.</summary>
    private async Task<Guid> RequestAsync(World w, Principal actor, string? payload = null)
    {
        using var scope = _fx.Scope();
        var approvals = scope.ServiceProvider.GetRequiredService<ApprovalService>();
        var result = await approvals.RequestAsync(
            actor, ScopeTarget.Project(w.ClientId, w.ProjectId),
            ApprovalKind.StalenessExemption, nameof(VexStatement),
            StalenessExemptions.SubjectId(w.ProjectId, w.BarePurl, w.Version),
            justification: "Analyzer only; never shipped.",
            payload: payload ?? Payload(w));
        Assert.True(result.Success, result.Error);
        return result.Value;
    }

    [SkippableFact]
    public async Task A_requested_exemption_does_not_relieve_the_score_until_it_is_approved()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var actors = await AppCovSeed.UsersAsync(db);
        var query = scope.ServiceProvider.GetRequiredService<CategoryFindingsQuery>();

        await RequestAsync(w, actors.Lead);

        // The whole point of the ticket. No statement exists, so nothing is exempt and
        // the component still costs what it cost.
        Assert.False(await db.VexStatements.AnyAsync(v => v.ProjectId == w.ProjectId));
        var stale = await query.SbomStalenessAsync(w.ProjectId, null);
        Assert.Null(stale.Single().ExemptVexId);
        Assert.Equal(0, (await query.SbomSummaryAsync(w.ProjectId, null))!.Exempt);
    }

    [SkippableFact]
    public async Task Approving_it_creates_the_statement_and_greys_the_component()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        Guid approvalId;
        Guid requesterId;
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            var actors = await AppCovSeed.UsersAsync(db);
            requesterId = actors.Lead.UserId;
            approvalId = await RequestAsync(w, actors.Lead);

            var approvals = scope.ServiceProvider.GetRequiredService<ApprovalService>();
            var decided = await approvals.DecideAsync(actors.InfoSec, approvalId, approve: true, note: "Agreed.");
            Assert.True(decided.Success, decided.Error);
        }

        using var read = _fx.Scope();
        var rdb = _fx.Db(read);
        var statement = await rdb.VexStatements.SingleAsync(v => v.ProjectId == w.ProjectId);
        Assert.Equal(VexStatement.StalenessAdvisoryId, statement.AdvisoryId);
        Assert.Equal(VexJustification.BuildTimeOnly, statement.Justification);

        // Authorship stays with whoever made the claim; the reviewer let it take effect.
        Assert.Equal(requesterId, statement.AuthorUserId);

        var query = read.ServiceProvider.GetRequiredService<CategoryFindingsQuery>();
        var stale = await query.SbomStalenessAsync(w.ProjectId, null);
        Assert.Equal(statement.Id, stale.Single().ExemptVexId);
    }

    [SkippableFact]
    public async Task Declining_it_writes_nothing_and_the_component_keeps_counting()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var actors = await AppCovSeed.UsersAsync(db);
        var approvals = scope.ServiceProvider.GetRequiredService<ApprovalService>();

        var approvalId = await RequestAsync(w, actors.Lead);
        Assert.True((await approvals.DecideAsync(
            actors.InfoSec, approvalId, approve: false, note: "It ships.")).Success);

        Assert.False(await db.VexStatements.AnyAsync(v => v.ProjectId == w.ProjectId));
        var query = scope.ServiceProvider.GetRequiredService<CategoryFindingsQuery>();
        Assert.Null((await query.SbomStalenessAsync(w.ProjectId, null)).Single().ExemptVexId);
    }

    [SkippableFact]
    public async Task The_requester_cannot_approve_their_own_exemption()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var actors = await AppCovSeed.UsersAsync(db);
        var approvals = scope.ServiceProvider.GetRequiredService<ApprovalService>();

        // The reason the kind exists. An InfoSec officer holds PublishVex and could
        // publish a statement directly, so the control is worth nothing unless it also
        // stops them approving the exemption they just asked for.
        var approvalId = await RequestAsync(w, actors.InfoSec);

        var decided = await approvals.DecideAsync(actors.InfoSec, approvalId, approve: true);

        Assert.False(decided.Success);
        Assert.False(await db.VexStatements.AnyAsync(v => v.ProjectId == w.ProjectId));
    }

    [SkippableFact]
    public async Task A_second_request_for_the_same_component_is_refused()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var actors = await AppCovSeed.UsersAsync(db);
        var approvals = scope.ServiceProvider.GetRequiredService<ApprovalService>();

        await RequestAsync(w, actors.Lead);

        // The subject id is derived from (project, purl, version) rather than random, so
        // ApprovalService's own duplicate guard applies. Two live requests for one
        // component would let a second approver rubber-stamp the copy.
        var again = await approvals.RequestAsync(
            actors.Lead, ScopeTarget.Project(w.ClientId, w.ProjectId),
            ApprovalKind.StalenessExemption, nameof(VexStatement),
            StalenessExemptions.SubjectId(w.ProjectId, w.BarePurl, w.Version),
            payload: Payload(w));

        Assert.False(again.Success);
        Assert.Equal(1, await db.PendingApprovals.CountAsync(
            a => a.ProjectId == w.ProjectId && a.Kind == ApprovalKind.StalenessExemption));
    }

    [SkippableFact]
    public async Task An_exemption_for_all_versions_is_a_different_request_from_one_pinned_version()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var actors = await AppCovSeed.UsersAsync(db);
        var approvals = scope.ServiceProvider.GetRequiredService<ApprovalService>();

        await RequestAsync(w, actors.Lead);

        // Version-bare and version-pinned exemptions mean different things — a bump
        // re-flags the pinned one and not the bare one — so collapsing them to one
        // subject would make the second request unfileable for no good reason.
        var bare = await approvals.RequestAsync(
            actors.Lead, ScopeTarget.Project(w.ClientId, w.ProjectId),
            ApprovalKind.StalenessExemption, nameof(VexStatement),
            StalenessExemptions.SubjectId(w.ProjectId, w.BarePurl, null),
            payload: Payload(w));

        Assert.True(bare.Success, bare.Error);
    }

    [SkippableFact]
    public async Task An_approval_carrying_no_justification_creates_nothing()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var actors = await AppCovSeed.UsersAsync(db);
        var approvals = scope.ServiceProvider.GetRequiredService<ApprovalService>();

        // StalenessExemptions.LoadAsync skips Justification None, so such a statement
        // would read as an exemption on the VEX page and silently not be one. Refusing
        // to create it beats creating a lie.
        var payload = JsonSerializer.Serialize(new VexDraft(
            VexStatement.StalenessAdvisoryId, w.BarePurl, w.Version,
            VexStatementStatus.NotAffected, VexJustification.None, "because", null));
        var approvalId = await RequestAsync(w, actors.Lead, payload);

        Assert.True((await approvals.DecideAsync(actors.InfoSec, approvalId, approve: true)).Success);
        Assert.False(await db.VexStatements.AnyAsync(v => v.ProjectId == w.ProjectId));
    }

    [SkippableFact]
    public async Task A_statement_published_between_the_request_and_the_decision_is_not_duplicated()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var actors = await AppCovSeed.UsersAsync(db);
        var approvals = scope.ServiceProvider.GetRequiredService<ApprovalService>();

        var approvalId = await RequestAsync(w, actors.Lead);

        db.VexStatements.Add(new VexStatement
        {
            ProjectId = w.ProjectId, Purl = w.BarePurl, ComponentVersion = w.Version,
            AdvisoryId = VexStatement.StalenessAdvisoryId, Status = VexStatementStatus.NotAffected,
            Justification = VexJustification.DoesNotShip, AuthorUserId = actors.InfoSec.UserId,
        });
        await db.SaveChangesAsync();

        Assert.True((await approvals.DecideAsync(actors.InfoSec, approvalId, approve: true)).Success);

        // One answer of record for one component, which is the invariant VexQuery's own
        // clash guard keeps on the direct path.
        Assert.Equal(1, await db.VexStatements.CountAsync(v => v.ProjectId == w.ProjectId));
    }
}
