using Tamp.Findings.Application.Suppressions;

namespace Tamp.Findings.Api.Services;

/// <summary>
/// Runs the suppression-expiry sweep (TFND-11 / F10.5).
///
/// Hourly rather than daily. A suppression's expiry is a date somebody chose,
/// and the finding coming back the same day is what they expect; a daily tick
/// can be up to 24 hours late, which on the morning of a release is the
/// difference between a gate blocking and a gate passing.
///
/// It also runs once at startup, so an instance that was down over the weekend
/// catches up rather than waiting for the next tick.
/// </summary>
public sealed class SuppressionExpiryWorker : BackgroundService
{
    private static readonly TimeSpan Interval = TimeSpan.FromHours(1);

    private readonly IServiceScopeFactory _scopes;
    private readonly ILogger<SuppressionExpiryWorker> _log;

    public SuppressionExpiryWorker(IServiceScopeFactory scopes, ILogger<SuppressionExpiryWorker> log)
    {
        _scopes = scopes;
        _log = log;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Staggered off the KEV worker's five seconds so two sweeps do not hit
        // a cold database at once on first boot.
        try { await Task.Delay(TimeSpan.FromSeconds(15), stoppingToken); }
        catch (OperationCanceledException) { return; }

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                using var scope = _scopes.CreateScope();
                var sweep = scope.ServiceProvider.GetRequiredService<SuppressionExpiryService>();

                await sweep.SweepAsync(DateTimeOffset.UtcNow, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                // One bad tick must not kill the worker. If it did, every later
                // expiry would silently stop taking effect and the first
                // symptom would be a finding nobody can explain the absence of.
                _log.LogError(ex, "The suppression-expiry sweep threw.");
            }

            try { await Task.Delay(Interval, stoppingToken); }
            catch (OperationCanceledException) { return; }
        }
    }
}
