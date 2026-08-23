namespace Tamp.Findings.Api.Authentication;

/// <summary>
/// Builds the identity-provider schemes when the host starts (TFND-111).
///
/// A hosted service rather than inline startup code because it needs the
/// database, and the database may not be reachable at the instant the process
/// comes up — a migration could still be running, or Postgres could be a
/// container that has not finished starting.
///
/// It does NOT fail the host if the load fails. An instance that cannot read
/// its provider table should still serve /health and render a sign-in page that
/// says there is no way in, rather than crash-looping where the only diagnosis
/// is a container log.
/// </summary>
public sealed class IdentityProviderStartup : IHostedService
{
    private readonly DynamicSchemeRegistry _registry;
    private readonly ILogger<IdentityProviderStartup> _log;

    public IdentityProviderStartup(DynamicSchemeRegistry registry, ILogger<IdentityProviderStartup> log)
    {
        _registry = registry;
        _log = log;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        try
        {
            await _registry.RebuildAsync(cancellationToken);
        }
        catch (Exception ex)
        {
            // RebuildAsync already swallows a database failure; this catches
            // everything else — a malformed provider row, a key ring problem —
            // for the same reason. Sign-in being unavailable is bad; the whole
            // instance refusing to start is worse, and harder to diagnose.
            _log.LogError(ex, "Identity providers could not be registered at startup.");
        }
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
