using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Data;

namespace Tamp.Findings.Api.Services;

// Looks up the "latest published version" + declared license for each
// SbomComponent against its native registry (nuget.org for pkg:nuget,
// registry.npmjs.org for pkg:npm; other ecosystems skipped for v1) and
// updates the component's LatestVersion/LatestReleasedAt/License. With
// those populated the SBOM ring on the Overview tab can show real
// yellow ("outdated, no CVE") share AND the License ring can populate.
//
// Syft's lockfile catalogers don't carry license info — pnpm-lock and
// packages.lock.json both omit it — so the registry call is the only
// way to fill it without spelunking node_modules / .nuspec files.
//
// Per-call HTTP concurrency is bounded so the public registries aren't
// hammered. Failures are logged and counted but don't fail the batch —
// individual transient errors are the norm at this scale.
public sealed class SbomEnrichmentService(
    FindingsDbContext db,
    IHttpClientFactory httpFactory,
    ILogger<SbomEnrichmentService> log)
{
    public sealed record Result(int Checked, int Updated, int Cleared, int Skipped, int Errors, int LicensesFilled);

    // Internal envelope so each lookup can return up to three signals.
    private sealed record Lookup(string? Latest, DateTimeOffset? LatestAt, string? License);

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
        var licensesFilled = 0;

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
                    _ => null,
                };
                if (lookup is null) return;

                if (lookup.Latest is { } latest)
                {
                    if (string.Equals(latest, c.Version, StringComparison.OrdinalIgnoreCase))
                    {
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
                        c.LatestReleasedAt = lookup.LatestAt;
                        Interlocked.Increment(ref updated);
                    }
                }

                // License: only fill if the SBOM didn't carry one. Don't
                // overwrite — the SBOM emitter (Syft / dotnet-CycloneDX)
                // is the better source when present.
                if (string.IsNullOrWhiteSpace(c.License) && !string.IsNullOrWhiteSpace(lookup.License))
                {
                    c.License = lookup.License;
                    Interlocked.Increment(ref licensesFilled);
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
        return new Result(checkedCount, updated, cleared, skipped, errors, licensesFilled);
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

    private async Task<Lookup?> LookupNuGetAsync(
        HttpClient http, string purl, CancellationToken ct)
    {
        var (name, _) = ParsePurl(purl, "pkg:nuget/");
        if (string.IsNullOrWhiteSpace(name)) return null;

        // azuresearch returns both the latest stable version AND the
        // license info in one call — cheaper than flatcontainer + a
        // second registration5-semver1 round-trip for license.
        var url = $"https://azuresearch-usnc.nuget.org/query?q=PackageId:{Uri.EscapeDataString(name)}&take=1&semVerLevel=2.0.0";
        using var resp = await http.GetAsync(url, ct);
        if (!resp.IsSuccessStatusCode) return null;
        using var stream = await resp.Content.ReadAsStreamAsync(ct);
        using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: ct);

        if (!doc.RootElement.TryGetProperty("data", out var data) ||
            data.ValueKind != JsonValueKind.Array ||
            data.GetArrayLength() == 0)
            return null;

        var entry = data[0];
        string? latest = null;
        if (entry.TryGetProperty("version", out var versionEl) &&
            versionEl.GetString() is { Length: > 0 } v &&
            !IsPrerelease(v))
        {
            latest = v;
        }

        // NuGet has three different fields depending on package age:
        //   licenseExpression — SPDX expression, new style (preferred)
        //   license           — string, legacy
        //   licenseUrl        — URL (last resort, often a generic page)
        string? license = null;
        if (entry.TryGetProperty("licenseExpression", out var lex) && lex.GetString() is { Length: > 0 } l1) license = l1;
        else if (entry.TryGetProperty("license", out var lic) && lic.GetString() is { Length: > 0 } l2) license = l2;

        // Microsoft / 1ES-published packages only set licenseUrl in the
        // search index. The actual licenseExpression lives in the catalog
        // entry, reached via registration5-semver1 → catalogEntry URL.
        // Two extra calls per missing-license package, gated on having
        // a known latest version.
        if (license is null && latest is not null)
        {
            license = await TryFetchNuGetLicenseFromCatalogAsync(http, name, latest, ct);
        }

        return new Lookup(latest, null, license);
    }

    private async Task<string?> TryFetchNuGetLicenseFromCatalogAsync(
        HttpClient http, string name, string version, CancellationToken ct)
    {
        try
        {
            var regUrl = $"https://api.nuget.org/v3/registration5-semver1/{name.ToLowerInvariant()}/{version.ToLowerInvariant()}.json";
            using var regResp = await http.GetAsync(regUrl, ct);
            if (!regResp.IsSuccessStatusCode) return null;
            using var regStream = await regResp.Content.ReadAsStreamAsync(ct);
            using var regDoc = await JsonDocument.ParseAsync(regStream, cancellationToken: ct);

            if (!regDoc.RootElement.TryGetProperty("catalogEntry", out var catEl)) return null;
            // catalogEntry is a URL string referencing the canonical
            // catalog data for this (id, version). Has to be fetched
            // separately — NuGet does not embed it inline at this layer.
            var catalogUrl = catEl.GetString();
            if (string.IsNullOrEmpty(catalogUrl)) return null;

            using var catResp = await http.GetAsync(catalogUrl, ct);
            if (!catResp.IsSuccessStatusCode) return null;
            using var catStream = await catResp.Content.ReadAsStreamAsync(ct);
            using var catDoc = await JsonDocument.ParseAsync(catStream, cancellationToken: ct);

            if (catDoc.RootElement.TryGetProperty("licenseExpression", out var lex) &&
                lex.GetString() is { Length: > 0 } l)
            {
                return l;
            }
            return null;
        }
        catch
        {
            return null;
        }
    }

    // SemVer prerelease has a '-' before any qualifier (e.g., "1.0.0-alpha").
    private static bool IsPrerelease(string ver)
    {
        var dash = ver.IndexOf('-');
        return dash >= 0;
    }

    // ----- npm lookup ---------------------------------------------------------

    private async Task<Lookup?> LookupNpmAsync(
        HttpClient http, string purl, CancellationToken ct)
    {
        var (name, _) = ParsePurl(purl, "pkg:npm/");
        if (string.IsNullOrWhiteSpace(name)) return null;

        // npm registry expects scoped names URL-encoded; @ → %40 and / → %2F.
        var encoded = name.Contains('/')
            ? name.Replace("@", "%40").Replace("/", "%2F")
            : Uri.EscapeDataString(name);

        var url = $"https://registry.npmjs.org/{encoded}";
        using var resp = await http.GetAsync(url, ct);
        if (!resp.IsSuccessStatusCode) return null;
        using var stream = await resp.Content.ReadAsStreamAsync(ct);
        using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: ct);

        string? latest = null;
        if (doc.RootElement.TryGetProperty("dist-tags", out var tags) &&
            tags.TryGetProperty("latest", out var latestEl))
        {
            latest = latestEl.GetString();
        }
        if (string.IsNullOrEmpty(latest)) return null;

        DateTimeOffset? releasedAt = null;
        if (doc.RootElement.TryGetProperty("time", out var time) &&
            time.TryGetProperty(latest, out var timeEl) &&
            timeEl.ValueKind == JsonValueKind.String &&
            DateTimeOffset.TryParse(timeEl.GetString(), out var parsed))
        {
            releasedAt = parsed;
        }

        // npm license can be either a string ("MIT") or — for older packages
        // — a "licenses" array of { type, url }. Prefer the per-latest-
        // version metadata if available since some packages relicense over
        // time; fall back to the root level.
        string? license = null;
        if (doc.RootElement.TryGetProperty("versions", out var versions) &&
            versions.TryGetProperty(latest, out var verMeta))
        {
            license = ExtractNpmLicense(verMeta);
        }
        license ??= ExtractNpmLicense(doc.RootElement);

        return new Lookup(latest, releasedAt, license);
    }

    private static string? ExtractNpmLicense(JsonElement el)
    {
        if (el.TryGetProperty("license", out var lic))
        {
            if (lic.ValueKind == JsonValueKind.String)
                return lic.GetString();
            if (lic.ValueKind == JsonValueKind.Object && lic.TryGetProperty("type", out var t))
                return t.GetString();
        }
        if (el.TryGetProperty("licenses", out var arr) && arr.ValueKind == JsonValueKind.Array && arr.GetArrayLength() > 0)
        {
            var first = arr[0];
            if (first.ValueKind == JsonValueKind.Object && first.TryGetProperty("type", out var t))
                return t.GetString();
            if (first.ValueKind == JsonValueKind.String)
                return first.GetString();
        }
        return null;
    }
}
