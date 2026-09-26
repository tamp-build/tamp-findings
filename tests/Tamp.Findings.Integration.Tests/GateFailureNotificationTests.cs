using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Risk;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Risk;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Integration.Tests;

// Gate-failure notification (TFND-122).
//
// When a freshly ingested build is blocked by its gates, a durable notification
// is recorded in the risk class. It reports BLOCKING gates — Fail, Unknown AND
// Error under the four-valued model — because a gate that could not be answered
// is not one that passed.
[Collection(DatabaseCollection.Name)]
public class GateFailureNotificationTests
{
    private readonly DatabaseFixture _fx;

    public GateFailureNotificationTests(DatabaseFixture fx) => _fx = fx;

    [SkippableFact]
    public async Task A_blocked_build_records_a_gates_blocking_notification()
    {
        Skip.IfNot(_fx.Available);

        var (projectId, sha) = await SeedBlockedBuildAsync();
        using var scope = _fx.Scope();
        var notifier = scope.ServiceProvider.GetRequiredService<GateFailureNotifier>();
        var db = _fx.Db(scope);

        await notifier.NotifyIfBlockedAsync(projectId, sha);

        var entry = db.AuditEntries
            .Where(a => a.ProjectId == projectId && a.Action == "gates.blocking")
            .OrderByDescending(a => a.At)
            .FirstOrDefault();

        Assert.NotNull(entry);
        Assert.Equal("ProjectGates", entry!.SubjectKind);
        Assert.Equal(AuditClass.Risk, entry.Class);
        Assert.Equal("system", entry.ActorLogin);
        Assert.Contains(GateKeys.CriticalSast, entry.Detail!, StringComparison.Ordinal);
    }

    [SkippableFact]
    public async Task An_identical_notification_is_not_recorded_twice()
    {
        Skip.IfNot(_fx.Available);

        // Several scanners for one build each trigger this; an unchanged blocking
        // picture must not stack duplicate notifications.
        var (projectId, sha) = await SeedBlockedBuildAsync();
        using var scope = _fx.Scope();
        var notifier = scope.ServiceProvider.GetRequiredService<GateFailureNotifier>();
        var db = _fx.Db(scope);

        await notifier.NotifyIfBlockedAsync(projectId, sha);
        await notifier.NotifyIfBlockedAsync(projectId, sha);

        var count = db.AuditEntries.Count(a => a.ProjectId == projectId && a.Action == "gates.blocking");
        Assert.Equal(1, count);
    }

    [SkippableFact]
    public async Task A_build_with_no_gates_enabled_records_nothing()
    {
        Skip.IfNot(_fx.Available);

        var (projectId, sha) = await SeedBlockedBuildAsync(enableGate: false);
        using var scope = _fx.Scope();
        var notifier = scope.ServiceProvider.GetRequiredService<GateFailureNotifier>();
        var db = _fx.Db(scope);

        await notifier.NotifyIfBlockedAsync(projectId, sha);

        Assert.Equal(0, db.AuditEntries.Count(a => a.ProjectId == projectId && a.Action == "gates.blocking"));
    }

    private async Task<(Guid ProjectId, string Sha)> SeedBlockedBuildAsync(bool enableGate = true)
    {
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);

        var suffix = Guid.NewGuid().ToString("N")[..8];
        var sha = suffix + "eeeeee";

        var policy = new RiskPolicy
        {
            Name = $"gate-policy-{suffix}",
            Config = RiskPolicyDefaults.BuildTampFederalV1(),
        };
        db.RiskPolicies.Add(policy);

        var gates = new ProjectGatesConfig();
        if (enableGate)
        {
            // No scan ran for this build, so criticalSast evaluates to Unknown —
            // which blocks under the four-valued model.
            gates.Gates[GateKeys.CriticalSast] = new GateConfig { Enabled = true, Threshold = 0 };
        }

        var client = new Client { Name = $"gate-client-{suffix}" };
        var project = new Project
        {
            ClientId = client.Id, Name = $"gate-project-{suffix}",
            RiskPolicyId = policy.Id, GatesConfig = gates,
        };
        var component = new Component { ProjectId = project.Id, Name = $"gate-component-{suffix}" };
        var version = new ComponentVersion
        {
            ComponentId = component.Id, VersionString = "1.0.0", CommitSha = sha, BranchName = "main",
        };

        db.Clients.Add(client);
        db.Projects.Add(project);
        db.Components.Add(component);
        db.ComponentVersions.Add(version);
        await db.SaveChangesAsync();

        return (project.Id, sha);
    }
}
