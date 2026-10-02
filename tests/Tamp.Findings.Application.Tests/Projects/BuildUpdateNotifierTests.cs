using Tamp.Findings.Application.Projects;

namespace Tamp.Findings.Application.Tests.Projects;

public class BuildUpdateNotifierTests
{
    [Fact]
    public async Task A_burst_of_publishes_coalesces_into_one_callback()
    {
        var n = new BuildUpdateNotifier(TimeSpan.FromMilliseconds(50));
        var project = Guid.NewGuid();
        var calls = 0;
        using var _ = n.Subscribe(project, () => { Interlocked.Increment(ref calls); return Task.CompletedTask; });

        for (var i = 0; i < 5; i++) n.Publish(project);
        await Task.Delay(300);

        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task Only_subscribers_of_that_project_are_called_and_disposed_ones_are_not()
    {
        var n = new BuildUpdateNotifier(TimeSpan.FromMilliseconds(20));
        var a = Guid.NewGuid(); var b = Guid.NewGuid();
        int aCalls = 0, bCalls = 0, goneCalls = 0;
        using var sa = n.Subscribe(a, () => { aCalls++; return Task.CompletedTask; });
        using var sb = n.Subscribe(b, () => { bCalls++; return Task.CompletedTask; });
        n.Subscribe(a, () => { goneCalls++; return Task.CompletedTask; }).Dispose();

        n.Publish(a);
        await Task.Delay(200);

        Assert.Equal((1, 0, 0), (aCalls, bCalls, goneCalls));
    }

    [Fact]
    public async Task A_throwing_subscriber_does_not_block_the_others()
    {
        var n = new BuildUpdateNotifier(TimeSpan.FromMilliseconds(20));
        var p = Guid.NewGuid();
        var ok = 0;
        using var s1 = n.Subscribe(p, () => throw new InvalidOperationException());
        using var s2 = n.Subscribe(p, () => { ok++; return Task.CompletedTask; });

        n.Publish(p);
        await Task.Delay(200);

        Assert.Equal(1, ok);
    }
}
