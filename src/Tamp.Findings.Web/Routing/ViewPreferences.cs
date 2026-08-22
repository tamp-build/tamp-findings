using Microsoft.JSInterop;

namespace Tamp.Findings.Web.Routing;

/// <summary>How dense a table should be. A persona setting, not a screen setting.</summary>
public enum Density
{
    /// <summary>The developer's default — several visits a day, wants room to read.</summary>
    Comfortable,

    /// <summary>The security lead's weekly sweep — wants more rows on screen.</summary>
    Compact,
}

/// <summary>
/// Per-viewer view preferences: row density and whether per-build deltas are
/// shown.
///
/// The hand-off lists both as first-class state because the four personas want
/// very different densities of information from the same data, and that was
/// "the central design problem" — the old UI served the developer only.
///
/// Persisted in <c>localStorage</c>, so this is per BROWSER rather than per
/// user account. That is the right weight for a remembered convenience and it
/// costs no schema change; a genuine per-user preference would need a column
/// on User and would then follow the person between machines. If that is ever
/// wanted, this is the seam to change and nothing above it moves.
///
/// Reads are best-effort. localStorage throws in a private window, when site
/// data is blocked, and during prerender (there is no browser yet), so every
/// access is guarded and falls back to the defaults rather than failing the
/// render.
/// </summary>
public sealed class ViewPreferences
{
    private const string DensityKey = "tamp.findings.density";
    private const string DeltasKey = "tamp.findings.deltas";

    private readonly IJSRuntime _js;
    private bool _loaded;

    public ViewPreferences(IJSRuntime js) => _js = js;

    public Density Density { get; private set; } = Density.Comfortable;

    /// <summary>
    /// Deltas default ON. The brief's ninth problem was that nothing was
    /// time-aware; a build score with no comparison is the state the redesign
    /// set out to fix, so opting OUT is the deliberate act.
    /// </summary>
    public bool ShowDeltas { get; private set; } = true;

    public event Action? Changed;

    /// <summary>CSS class for the current density, applied at the shell.</summary>
    public string DensityClass => Density == Density.Compact ? "density-compact" : "";

    /// <summary>
    /// Call once from the shell after the first interactive render. Before
    /// that there is no browser to read from — calling during prerender throws.
    /// </summary>
    public async Task LoadAsync()
    {
        if (_loaded) return;
        _loaded = true;

        var density = await TryGetAsync(DensityKey);
        if (Enum.TryParse<Density>(density, ignoreCase: true, out var parsed)) Density = parsed;

        var deltas = await TryGetAsync(DeltasKey);
        if (bool.TryParse(deltas, out var on)) ShowDeltas = on;

        Changed?.Invoke();
    }

    public async Task SetDensityAsync(Density density)
    {
        if (Density == density) return;
        Density = density;
        Changed?.Invoke();
        await TrySetAsync(DensityKey, density.ToString());
    }

    public async Task SetShowDeltasAsync(bool show)
    {
        if (ShowDeltas == show) return;
        ShowDeltas = show;
        Changed?.Invoke();
        await TrySetAsync(DeltasKey, show ? "true" : "false");
    }

    // The preference is a convenience. Losing it must never break a render, so
    // every failure mode — no browser yet, private window, blocked site data,
    // a closed circuit — resolves to "use the default" rather than throwing.
    private async Task<string?> TryGetAsync(string key)
    {
        try { return await _js.InvokeAsync<string?>("tampFindings.get", key); }
        catch { return null; }
    }

    private async Task TrySetAsync(string key, string value)
    {
        try { await _js.InvokeVoidAsync("tampFindings.set", key, value); }
        catch { /* preference not persisted; the in-memory value still applies */ }
    }
}
