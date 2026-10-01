using System.Collections.Concurrent;

namespace Tamp.Findings.Application.Projects;

/// <summary>
/// In-process "a project's latest build changed" signal (TFND-224). Ingest publishes after the score
/// snapshot is saved; unpinned views subscribe and re-load. Bursts (one build posts many ingests) are
/// coalesced per project. Single-replica only — scaling the API out needs Postgres LISTEN/NOTIFY.
/// </summary>
public sealed class BuildUpdateNotifier
{
    private readonly ConcurrentDictionary<Guid, ConcurrentDictionary<Guid, Func<Task>>> _subs = new();
    private readonly ConcurrentDictionary<Guid, int> _pending = new();
    private readonly TimeSpan _debounce;

    public BuildUpdateNotifier() : this(TimeSpan.FromSeconds(1.5)) { }
    public BuildUpdateNotifier(TimeSpan debounce) => _debounce = debounce;

    public IDisposable Subscribe(Guid projectId, Func<Task> onUpdated)
    {
        var id = Guid.NewGuid();
        _subs.GetOrAdd(projectId, _ => new())[id] = onUpdated;
        return new Sub(() =>
        {
            if (_subs.TryGetValue(projectId, out var d)) d.TryRemove(id, out _);
        });
    }

    public void Publish(Guid projectId)
    {
        if (!_subs.TryGetValue(projectId, out var d) || d.IsEmpty) return;
        if (!_pending.TryAdd(projectId, 1)) return;   // a flush is already scheduled; it will see this change
        _ = Task.Run(async () =>
        {
            await Task.Delay(_debounce);
            _pending.TryRemove(projectId, out _);
            if (!_subs.TryGetValue(projectId, out var subs)) return;
            foreach (var cb in subs.Values)
            {
                try { await cb(); } catch { /* a dead circuit must not block the others */ }
            }
        });
    }

    private sealed class Sub(Action dispose) : IDisposable
    {
        private int _done;
        public void Dispose() { if (Interlocked.Exchange(ref _done, 1) == 0) dispose(); }
    }
}
