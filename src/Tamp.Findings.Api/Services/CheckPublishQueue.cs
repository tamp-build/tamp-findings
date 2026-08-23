using System.Threading.Channels;
using Tamp.Findings.Application.GitHub;

namespace Tamp.Findings.Api.Services;

/// <summary>
/// Publishing check runs OUT OF BAND of the ingest that triggers them
/// (TFND-23).
///
/// An ingest must not wait on GitHub. The findings are already stored by the
/// time this is queued; the check is a notification, and a notification that
/// holds a CI step open — or fails it because api.github.com was slow — is
/// worse than a late one.
///
/// Bounded, and it DROPS rather than blocks when full. A burst of ingests must
/// never become backpressure on the ingest endpoint, which is the one thing in
/// this product that has to keep accepting evidence.
/// </summary>
public sealed class CheckPublishQueue
{
    private readonly Channel<CheckPublishRequest> _channel =
        Channel.CreateBounded<CheckPublishRequest>(new BoundedChannelOptions(256)
        {
            FullMode = BoundedChannelFullMode.DropWrite,
            SingleReader = true,
        });

    private readonly ILogger<CheckPublishQueue> _log;

    public CheckPublishQueue(ILogger<CheckPublishQueue> log) => _log = log;

    public void Enqueue(Guid projectId, string commitSha)
    {
        if (string.IsNullOrWhiteSpace(commitSha)) return;

        if (!_channel.Writer.TryWrite(new CheckPublishRequest(projectId, commitSha)))
        {
            // Logged rather than swallowed. A dropped check is a check that
            // never appears on a pull request, which looks identical to one
            // that passed — so the reason has to exist somewhere.
            _log.LogWarning(
                "Check-run queue is full; dropped the publish for {Project}@{Commit}. "
                + "Ingests are outrunning GitHub.",
                projectId, commitSha);
        }
    }

    public IAsyncEnumerable<CheckPublishRequest> ReadAllAsync(CancellationToken ct) =>
        _channel.Reader.ReadAllAsync(ct);
}

public sealed record CheckPublishRequest(Guid ProjectId, string CommitSha);

/// <summary>
/// Drains the queue, one publish at a time.
///
/// Serial on purpose: GitHub rate-limits per installation, and a parallel
/// drain would spend the budget faster without delivering anything sooner —
/// the queue is not the bottleneck, the API is.
/// </summary>
public sealed class CheckPublishWorker : BackgroundService
{
    private readonly CheckPublishQueue _queue;
    private readonly IServiceScopeFactory _scopes;
    private readonly ILogger<CheckPublishWorker> _log;

    public CheckPublishWorker(
        CheckPublishQueue queue, IServiceScopeFactory scopes, ILogger<CheckPublishWorker> log)
    {
        _queue = queue;
        _scopes = scopes;
        _log = log;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await foreach (var request in _queue.ReadAllAsync(stoppingToken))
        {
            try
            {
                using var scope = _scopes.CreateScope();
                var publisher = scope.ServiceProvider.GetRequiredService<GitHubCheckPublisher>();

                var outcome = await publisher.PublishAsync(
                    request.ProjectId, request.CommitSha, stoppingToken);

                if (outcome.Success)
                {
                    _log.LogInformation("Published a {Conclusion} check for {Project}@{Commit}.",
                        outcome.Conclusion, request.ProjectId, request.CommitSha);
                }
                else
                {
                    // Debug, not warning: "this project has no repository" is
                    // the common case and the correct one, and logging it at
                    // warning would train operators to ignore the level.
                    _log.LogDebug("No check published for {Project}@{Commit}: {Reason}",
                        request.ProjectId, request.CommitSha, outcome.Reason);
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                // One bad request must not kill the worker. If it did, every
                // later check would silently stop appearing, and the first
                // symptom would be a pull request merging without one.
                _log.LogError(ex, "Publishing a check for {Project}@{Commit} threw.",
                    request.ProjectId, request.CommitSha);
            }
        }
    }
}
