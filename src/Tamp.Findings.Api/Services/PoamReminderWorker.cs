using Tamp.Findings.Application.Poam;

namespace Tamp.Findings.Api.Services;

/// <summary>
/// Runs the POA&amp;M due-date reminder sweep (TFND-121; ADR 0005 — replaces the
/// Elsa Timer workflow).
///
/// Daily, not hourly: a due date has day resolution, and more than one reminder
/// a day about the same date is how a channel gets muted. Runs once at startup
/// so an instance that was down over the weekend catches up rather than waiting
/// for the next tick.
/// </summary>
public sealed class PoamReminderWorker : BackgroundService
{
    private static readonly TimeSpan Interval = TimeSpan.FromDays(1);

    private readonly IServiceScopeFactory _scopes;
    private readonly ILogger<PoamReminderWorker> _log;

    public PoamReminderWorker(IServiceScopeFactory scopes, ILogger<PoamReminderWorker> log)
    {
        _scopes = scopes;
        _log = log;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Staggered off the other startup sweeps so they do not hit a cold
        // database at once on first boot.
        try { await Task.Delay(TimeSpan.FromSeconds(20), stoppingToken); }
        catch (OperationCanceledException) { return; }

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                using var scope = _scopes.CreateScope();
                var reminders = scope.ServiceProvider.GetRequiredService<PoamReminderService>();
                await reminders.SweepAsync(DateTimeOffset.UtcNow, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                // One bad tick must not kill the worker, or every later reminder
                // silently stops and the first symptom is an overdue POA&M
                // nobody was warned about.
                _log.LogError(ex, "The POA&M due-date reminder sweep threw.");
            }

            try { await Task.Delay(Interval, stoppingToken); }
            catch (OperationCanceledException) { return; }
        }
    }
}
