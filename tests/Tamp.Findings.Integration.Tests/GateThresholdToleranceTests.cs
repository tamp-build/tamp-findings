using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Policy;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Risk;

namespace Tamp.Findings.Integration.Tests;

// Sonar S1244/S1751 follow-up: gate thresholds are doubles, so "did the threshold change" compares with a
// tolerance (a value that differs only by floating-point noise is not a change), and a negative threshold on
// an enabled gate is still rejected after the loop-with-a-return was refactored.
[Collection(DatabaseCollection.Name)]
public class GateThresholdToleranceTests
{
    private readonly DatabaseFixture _fx;
    public GateThresholdToleranceTests(DatabaseFixture fx) => _fx = fx;

    private static GateRow Row(double? threshold, bool enabled = true) =>
        new(GateKeys.CriticalCves, "Critical CVEs", "d", enabled, threshold, HasThreshold: true);

    private async Task<(Guid ProjectId, Principal Admin)> SeedAsync()
    {
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var s = Guid.NewGuid().ToString("N")[..8];
        var user = new User { Login = $"gt-{s}", DisplayName = "gt", Email = $"gt{s}@e.test", IsApproved = true };
        var client = new Client { Name = $"gt-client-{s}" };
        var project = new Project { ClientId = client.Id, Name = $"gt-project-{s}" };
        db.Users.Add(user); db.Clients.Add(client); db.Projects.Add(project);
        await db.SaveChangesAsync();
        return (project.Id, Principal.For(user.Id, user.Login, isAdmin: true, []));
    }

    [SkippableFact]
    public async Task A_threshold_that_differs_only_by_floating_point_noise_is_not_a_change()
    {
        Skip.IfNot(_fx.Available);
        var (projectId, admin) = await SeedAsync();
        using var scope = _fx.Scope();
        var gates = scope.ServiceProvider.GetRequiredService<GateService>();

        var first = await gates.SaveAsync(admin, ScopeTarget.Instance, projectId, [Row(3.0)]);
        var noise = await gates.SaveAsync(admin, ScopeTarget.Instance, projectId, [Row(3.0 + 1e-12)]);
        var real = await gates.SaveAsync(admin, ScopeTarget.Instance, projectId, [Row(4.0)]);

        Assert.True(first.Success);
        Assert.Equal(0, noise.Value);   // same threshold, modulo noise: nothing recorded
        Assert.Equal(1, real.Value);    // a real change is still recorded
    }

    [SkippableFact]
    public async Task A_negative_threshold_on_an_enabled_gate_is_rejected_but_a_disabled_one_is_not()
    {
        Skip.IfNot(_fx.Available);
        var (projectId, admin) = await SeedAsync();
        using var scope = _fx.Scope();
        var gates = scope.ServiceProvider.GetRequiredService<GateService>();

        var enabled = await gates.SaveAsync(admin, ScopeTarget.Instance, projectId, [Row(-1, enabled: true)]);
        var disabled = await gates.SaveAsync(admin, ScopeTarget.Instance, projectId, [Row(-1, enabled: false)]);

        Assert.False(enabled.Success);
        Assert.Contains("negative", enabled.Error);
        Assert.True(disabled.Success);
    }
}
