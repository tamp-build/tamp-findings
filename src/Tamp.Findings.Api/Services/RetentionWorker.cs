using Tamp.Findings.Application.Retention;

namespace Tamp.Findings.Api.Services;

/// <summary>
/// Runs the retention sweep (TFND-13 / F12.4).
///
/// Daily, and unlike the suppression sweep that is the right cadence: nobody
/// needs a finding deleted within the hour, and a destructive job that runs
/// often is a destructive job with more chances to be wrong.
///
/// It does NOT run at startup. A retention sweep is irreversible, and a crash
/// loop that restarts the host every thirty seconds would otherwise run it
/// every thirty seconds. Waiting a full period costs a day of keeping data,
/// which is the direction to be wrong in.
/// </summary>
public sealed class RetentionWorker : BackgroundService
{
    private static readonly TimeSpan Interval = TimeSpan.FromHours(24);

    private readonly IServiceScopeFactory _scopes;
    private readonly ILogger<RetentionWorker> _log;

    public RetentionWorker(IServiceScopeFactory scopes, ILogger<RetentionWorker> log)
    {
        _scopes = scopes;
        _log = log;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try { await Task.Delay(Interval, stoppingToken); }
            catch (OperationCanceledException) { return; }

            try
            {
                using var scope = _scopes.CreateScope();
                var retention = scope.ServiceProvider.GetRequiredService<RetentionService>();

                await retention.SweepAsync(DateTimeOffset.UtcNow, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                // Loud. A retention sweep that stopped working means an
                // instance is keeping data it was told to delete, which is a
                // data-handling commitment quietly going unmet.
                _log.LogError(ex, "The retention sweep threw. Data is being kept beyond its window.");
            }
        }
    }
}
