using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Data;

namespace Tamp.Findings.Api.Services;

// Looks up the "latest published version" for each SbomComponent against
// its native registry (nuget.org for pkg:nuget, registry.npmjs.org for
// pkg:npm; other ecosystems skipped for v1) and updates the component's
// LatestVersion + LatestReleasedAt. With that populated, the SBOM ring
// on the Overview tab can show real yellow ("outdated, no CVE") share.
//
// Per-call HTTP concurrency is bounded so the public registries aren't
// hammered. Failures are logged and counted but don't fail the batch —
// individual transient errors are the norm at this scale.
public sealed class SbomEnrichmentService(
    FindingsDbContext db,
    IHttpClientFactory httpFactory,
    ILogger<SbomEnrichmentService> log)
{
    public sealed record Result(int Checked, int Updated, int Cleared, int Skipped, int Errors);

    public async Task<Result> EnrichAsync(Guid? snapshotId, CancellationToken ct)
    {
        var http = httpFactory.CreateClient("registries");
        http.Timeout = TimeSpan.FromSeconds(8);
        http.DefaultRequestHeaders.UserAgent.ParseAdd("tamp.findings/0.1 (+local)");

        var q = db.SbomComponents.AsQueryable();
        if (snapshotId is { } id) q = q.Where(c => c.SbomSnapshotId == id);
        var components = await q.ToListAsync(ct);

        var checkedCount = 0;
        var updated = 0;
        var cleared = 0;
        var skipped = 0;
        var errors = 0;

        var sem = new SemaphoreSlim(initialCount: 8);
        var tasks = components.Select(async c =>
        {
            await sem.WaitAsync(ct);
            try
            {
                var ecosystem = GetEcosystem(c.Purl);
                if (ecosystem is null)
                {
                    Interlocked.Increment(ref skipped);
                    return;
                }
                Interlocked.Increment(ref checkedCount);

                var lookup = ecosystem switch
                {
                    "nuget" => await LookupNuGetAsync(http, c.Purl, ct),
                    "npm" => await LookupNpmAsync(http, c.Purl, ct),
                    _ => (null, (DateTimeOffset?)null),
                };
                var (latest, latestAt) = lookup;
                if (latest is null) return; // registry returned no usable info

                if (string.Equals(latest, c.Version, StringComparison.OrdinalIgnoreCase))
                {
                    // Current IS latest — clear any stale annotation so the
                    // outdated bucket doesn't lie. CurrentReleasedAt could
                    // be filled the same way; not critical for the ring.
                    if (c.LatestVersion is not null || c.LatestReleasedAt is not null)
                    {
                        c.LatestVersion = null;
                        c.LatestReleasedAt = null;
                        Interlocked.Increment(ref cleared);
                    }
                }
                else
                {
                    c.LatestVersion = latest;
                    c.LatestReleasedAt = latestAt;
                    Interlocked.Increment(ref updated);
                }
            }
            catch (Exception ex)
            {
                Interlocked.Increment(ref errors);
                log.LogDebug(ex, "enrich failed for {purl}", c.Purl);
            }
            finally
            {
                sem.Release();
            }
        }).ToArray();

        await Task.WhenAll(tasks);
        await db.SaveChangesAsync(ct);
        return new Result(checkedCount, updated, cleared, skipped, errors);
    }

    // ----- ecosystem detection ------------------------------------------------

    private static string? GetEcosystem(string purl)
    {
        if (purl.StartsWith("pkg:nuget/", StringComparison.Ordinal)) return "nuget";
        if (purl.StartsWith("pkg:npm/", StringComparison.Ordinal)) return "npm";
        return null;
    }

    // ----- PURL parsing -------------------------------------------------------
    //
    // purl spec: pkg:<type>/<namespace>?/<name>@<version>?<qualifiers>?#<subpath>?
    // Namespace is rare for nuget (always empty), required for scoped npm.

    private static (string Name, string? Version) ParsePurl(string purl, string prefix)
    {
        var rest = purl[prefix.Length..];
        var atIdx = rest.IndexOf('@');
        var name = atIdx >= 0 ? rest[..atIdx] : rest;
        var version = atIdx >= 0 ? rest[(atIdx + 1)..] : null;
        // Strip qualifiers / subpath if present.
        var qIdx = version?.IndexOfAny(['?', '#']);
        if (version is not null && qIdx is > 0) version = version[..qIdx.Value];
        return (Uri.UnescapeDataString(name), version is null ? null : Uri.UnescapeDataString(version));
    }

    // ----- NuGet lookup -------------------------------------------------------

    private async Task<(string? Latest, DateTimeOffset? LatestAt)> LookupNuGetAsync(
        HttpClient http, string purl, CancellationToken ct)
    {
        var (name, _) = ParsePurl(purl, "pkg:nuget/");
        if (string.IsNullOrWhiteSpace(name)) return (null, null);

        // v3 flatcontainer is the cheapest way to enumerate versions; it
        // returns a sorted ascending versions array. We don't get release
        // dates here — a follow-up could hit registration5-semver1 for
        // each newer version to get `published`, but for the yellow ring
        // we only need the version string.
        var url = $"https://api.nuget.org/v3-flatcontainer/{name.ToLowerInvariant()}/index.json";
        using var resp = await http.GetAsync(url, ct);
        if (!resp.IsSuccessStatusCode) return (null, null);
        using var stream = await resp.Content.ReadAsStreamAsync(ct);
        using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: ct);
        if (!doc.RootElement.TryGetProperty("versions", out var arr) || arr.ValueKind != JsonValueKind.Array)
            return (null, null);

        string? latestStable = null;
        foreach (var v in arr.EnumerateArray())
        {
            var s = v.GetString();
            if (string.IsNullOrEmpty(s)) continue;
            if (IsPrerelease(s)) continue;
            latestStable = s; // array is ascending; last stable wins
        }
        return (latestStable, null);
    }

    // SemVer prerelease has a '-' before any qualifier (e.g., "1.0.0-alpha").
    private static bool IsPrerelease(string ver)
    {
        var dash = ver.IndexOf('-');
        return dash >= 0;
    }

    // ----- npm lookup ---------------------------------------------------------

    private async Task<(string? Latest, DateTimeOffset? LatestAt)> LookupNpmAsync(
        HttpClient http, string purl, CancellationToken ct)
    {
        var (name, _) = ParsePurl(purl, "pkg:npm/");
        if (string.IsNullOrWhiteSpace(name)) return (null, null);

        // npm registry expects scoped names URL-encoded; @ → %40 and / → %2F.
        // Tooling-friendly: just encode the whole name conservatively.
        var encoded = name.Contains('/')
            ? name.Replace("@", "%40").Replace("/", "%2F")
            : Uri.EscapeDataString(name);

        var url = $"https://registry.npmjs.org/{encoded}";
        using var resp = await http.GetAsync(url, ct);
        if (!resp.IsSuccessStatusCode) return (null, null);
        using var stream = await resp.Content.ReadAsStreamAsync(ct);
        using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: ct);

        string? latest = null;
        if (doc.RootElement.TryGetProperty("dist-tags", out var tags) &&
            tags.TryGetProperty("latest", out var latestEl))
        {
            latest = latestEl.GetString();
        }
        if (string.IsNullOrEmpty(latest)) return (null, null);

        DateTimeOffset? releasedAt = null;
        if (doc.RootElement.TryGetProperty("time", out var time) &&
            time.TryGetProperty(latest, out var timeEl) &&
            timeEl.ValueKind == JsonValueKind.String &&
            DateTimeOffset.TryParse(timeEl.GetString(), out var parsed))
        {
            releasedAt = parsed;
        }
        return (latest, releasedAt);
    }
}
