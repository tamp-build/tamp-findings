using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Auditing;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Compliance;
using Tamp.Findings.Application.Mcp;
using Tamp.Findings.Domain.Compliance;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Integration.Tests;

// Control catalog / disposition queries, the audit write path and AgentContext.
[Collection(DatabaseCollection.Name)]
public class AppCovComplianceAuditTests
{
    private readonly DatabaseFixture _fx;
    public AppCovComplianceAuditTests(DatabaseFixture fx) => _fx = fx;

    [SkippableFact]
    public async Task Catalog_query_reads_current_catalog_and_frameworks()
    {
        Skip.IfNot(_fx.Available);
        using var scope = _fx.Scope();
        var q = scope.ServiceProvider.GetRequiredService<ControlCatalogQuery>();

        var summary = await q.CurrentCatalogAsync();
        var controls = await q.ControlsAsync();
        if (summary is null)
        {
            Assert.Empty(controls);
            Assert.Null(await q.ControlAsync("AC-3"));
        }
        else
        {
            Assert.Equal(summary.ControlCount, controls.Count);
            Assert.True(summary.PriorVersions >= 0);
            var first = controls[0];
            Assert.Equal(first.Id, (await q.ControlAsync(first.Id.ToLowerInvariant()))!.Id);
            Assert.Null(await q.ControlAsync("ZZ-999"));
            Assert.Equal(controls.OrderBy(c => c.Family).ThenBy(c => c.Id, StringComparer.Ordinal).Select(c => c.Id), controls.Select(c => c.Id));
        }
        Assert.NotNull(await q.FrameworksAsync());
    }

    [SkippableFact]
    public async Task Disposition_query_returns_null_until_a_framework_is_assigned()
    {
        Skip.IfNot(_fx.Available);
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var q = scope.ServiceProvider.GetRequiredService<ControlDispositionQuery>();
        var (client, project) = await AppCovSeed.ClientProjectAsync(db, "cd");

        Assert.Null(await q.ForProjectAsync(Guid.NewGuid(), null));
        Assert.Null(await q.ForProjectAsync(project.Id, null));

        var none = new Framework { Slug = $"cov-none-{Guid.NewGuid():N}", Name = "none", Source = "t", Version = "1", Baseline = BaselineLevel.None };
        var moderate = new Framework { Slug = $"cov-mod-{Guid.NewGuid():N}", Name = "mod", Source = "t", Version = "1", Baseline = BaselineLevel.Moderate };
        db.Frameworks.AddRange(none, moderate);
        await db.SaveChangesAsync();

        var c = await db.Clients.FindAsync(client.Id);
        c!.FrameworkId = none.Id;
        await db.SaveChangesAsync();
        Assert.Null(await q.ForProjectAsync(project.Id, null));

        c.FrameworkId = moderate.Id;
        await db.SaveChangesAsync();
        var coverage = await q.ForProjectAsync(project.Id, null);
        var catalogPresent = await db.ControlCatalogs.AnyAsync(x => x.IsCurrent);
        if (!catalogPresent) Assert.Null(coverage);
        else
        {
            Assert.NotNull(coverage);
            Assert.Equal(coverage!.InScope, coverage.Gated + coverage.Inherited + coverage.NotApplicable + coverage.Unmapped);
            var capped = await q.ForProjectAsync(project.Id, ComponentCapability.Source | ComponentCapability.Deps);
            Assert.Equal(coverage.InScope, capped!.InScope);
        }
    }

    [SkippableFact]
    public async Task Audit_log_records_and_filters()
    {
        Skip.IfNot(_fx.Available);
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var audit = scope.ServiceProvider.GetRequiredService<AuditLog>();
        var actors = await AppCovSeed.UsersAsync(db);
        var (client, project) = await AppCovSeed.ClientProjectAsync(db, "al");
        var target = ScopeTarget.Project(client.Id, project.Id);
        var multi = Principal.For(Guid.NewGuid(), $"multi-{Guid.NewGuid():N}", true,
            [ProjectRole.LeadDev, ProjectRole.Architect, ProjectRole.Auditor]);
        var arch = Principal.For(Guid.Empty, "arch", false, [ProjectRole.Architect]);
        var auditor = Principal.For(Guid.NewGuid(), "aud", false, [ProjectRole.Auditor]);

        Assert.Throws<ArgumentNullException>(() => audit.Record(null!, "x", AuditClass.Other));
        Assert.Throws<ArgumentException>(() => audit.Record(actors.Admin, " ", AuditClass.Other));
        Assert.Throws<ArgumentException>(() => audit.RecordIngest(Guid.NewGuid(), "t", null, null, " "));

        var e1 = audit.Record(actors.InfoSec, "cov.a", AuditClass.Risk, target, project.Id, "Project", "d");
        var e2 = audit.Record(multi, "cov.b", AuditClass.Access, target);
        var e3 = audit.Record(arch, "cov.c", AuditClass.Other, target);
        var e4 = audit.Record(auditor, "cov.d", AuditClass.Other, target);
        var e5 = audit.Record(actors.Viewer, "cov.e", AuditClass.Other, target);
        var tokenId = Guid.NewGuid();
        var i1 = audit.RecordIngest(tokenId, "label", Guid.NewGuid(), "alice", "cov.ingest", target, "scan");
        var i2 = audit.RecordIngest(tokenId, "label", null, null, "cov.ingest2", target, null);
        var s1 = audit.RecordSystem("cov.sys", AuditClass.Other, target, project.Id, "Project", "auto");
        await db.SaveChangesAsync();

        Assert.Equal(ProjectRole.InfoSecOfficer, e1.ActorRole);
        Assert.Equal(ProjectRole.Architect, e2.ActorRole);
        Assert.True(e2.ActorWasAdmin);
        Assert.Equal(ProjectRole.Architect, e3.ActorRole);
        Assert.Null(e3.UserId);
        Assert.Equal(ProjectRole.Auditor, e4.ActorRole);
        Assert.Null(e5.ActorRole);
        Assert.Equal("via token 'label': scan", i1.Detail);
        Assert.Equal("token:label", i2.ActorLogin);
        Assert.Equal("system", s1.ActorLogin);

        var all = await audit.QueryAsync(projectId: project.Id);
        Assert.Equal(8, all.Count);
        Assert.Equal(8, (await audit.QueryAsync(clientId: client.Id)).Count);
        Assert.Single(await audit.QueryAsync(projectId: project.Id, @class: AuditClass.Risk));
        Assert.Single(await audit.QueryAsync(projectId: project.Id, actorLogin: "alice"));
        Assert.Empty(await audit.QueryAsync(projectId: project.Id, since: DateTimeOffset.UtcNow.AddMinutes(5)));
        Assert.Empty(await audit.QueryAsync(projectId: project.Id, until: DateTimeOffset.UtcNow.AddDays(-1)));
        Assert.Equal(8, (await audit.QueryAsync(projectId: project.Id, since: DateTimeOffset.UtcNow.AddMinutes(-5), until: DateTimeOffset.UtcNow.AddMinutes(5))).Count);
        Assert.Single(await audit.QueryAsync(projectId: project.Id, take: 0));
    }

    [Fact]
    public void Agent_context_attaches_once_and_requires_identity()
    {
        var ctx = new AgentContext();
        Assert.Null(ctx.Identity);
        Assert.Throws<InvalidOperationException>(() => ctx.Require());
        var id = new AgentIdentity(Guid.NewGuid(), "agent", Principal.For(Guid.NewGuid(), "a", false, []), ScopeTarget.Instance);
        ctx.Attach(id);
        Assert.Same(id, ctx.Identity);
        Assert.Same(id, ctx.Require());
        Assert.Throws<InvalidOperationException>(() => ctx.Attach(id));
    }
}
