using System.IO.Compression;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Risk;

namespace Tamp.Findings.Api.Services;

// Pulls known-malicious packages from OSV (the OpenSSF malicious-packages corpus is published there as
// MAL-* advisories) into the unauthorized-component list (CM-8(3), TFND-211). Per-ecosystem all.zip
// archives are streamed to a temp file (npm is ~200 MB) and only the MAL-* entries are parsed. A
// conditional GET (ETag) skips an unchanged archive. Failures keep the existing list: a feed outage
// must never empty the denylist.
public sealed class MaliciousPackageFeedSyncService(
    IHttpClientFactory httpClientFactory,
    FindingsDbContext db,
    ILogger<MaliciousPackageFeedSyncService> log)
{
    public const string Source = "osv-malicious";
    public static readonly string[] Ecosystems = ["NuGet", "npm"];
    private static string Url(string eco) => $"https://osv-vulnerabilities.storage.googleapis.com/{eco}/all.zip";

    // ETag per ecosystem, process-local: a restart simply re-downloads once.
    private static readonly Dictionary<string, string> ETags = new();

    public sealed record SyncResult(int Ecosystems, int Inserted, int Updated, int Skipped, IReadOnlyList<string> Errors);

    public async Task<SyncResult> SyncAsync(CancellationToken ct = default)
    {
        int inserted = 0, updated = 0, skipped = 0;
        var errors = new List<string>();
        foreach (var eco in Ecosystems)
        {
            try
            {
                var (i, u, notModified) = await SyncEcosystemAsync(eco, ct);
                inserted += i; updated += u;
                if (notModified) skipped++;
            }
            catch (Exception ex) when (!ct.IsCancellationRequested)
            {
                log.LogWarning(ex, "malicious-package sync failed for {Eco}; keeping existing entries", eco);
                errors.Add($"{eco}: {ex.Message}");
            }
        }
        return new SyncResult(Ecosystems.Length, inserted, updated, skipped, errors);
    }

    private async Task<(int Inserted, int Updated, bool NotModified)> SyncEcosystemAsync(string eco, CancellationToken ct)
    {
        var http = httpClientFactory.CreateClient("registries");
        http.Timeout = TimeSpan.FromMinutes(10);
        using var req = new HttpRequestMessage(HttpMethod.Get, Url(eco));
        if (ETags.TryGetValue(eco, out var etag)) req.Headers.TryAddWithoutValidation("If-None-Match", etag);
        using var resp = await http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);
        if (resp.StatusCode == System.Net.HttpStatusCode.NotModified) return (0, 0, true);
        resp.EnsureSuccessStatusCode();

        var tmp = Path.Combine(Path.GetTempPath(), $"osv-{eco}-{Guid.NewGuid():N}.zip");
        try
        {
            await using (var fs = File.Create(tmp))
                await resp.Content.CopyToAsync(fs, ct);

            var found = new List<MalEntry>();
            using (var zip = ZipFile.OpenRead(tmp))
            {
                foreach (var entry in zip.Entries.Where(e => e.Name.StartsWith("MAL-", StringComparison.Ordinal)))
                {
                    await using var s = entry.Open();
                    using var doc = await JsonDocument.ParseAsync(s, cancellationToken: ct);
                    found.AddRange(Parse(doc.RootElement, eco));
                }
            }

            var (ins, upd) = await UpsertAsync(found, ct);
            if (resp.Headers.ETag is { } tag) ETags[eco] = tag.ToString();
            log.LogInformation("malicious-package sync {Eco}: {Found} entries, {Ins} new, {Upd} updated", eco, found.Count, ins, upd);
            return (ins, upd, false);
        }
        finally
        {
            try { File.Delete(tmp); } catch { /* best effort */ }
        }
    }

    internal sealed record MalEntry(string Purl, List<string> Versions, string Id, string? Summary);

    // One OSV advisory yields one entry per affected package of this ecosystem.
    internal static IEnumerable<MalEntry> Parse(JsonElement root, string eco)
    {
        var id = root.TryGetProperty("id", out var idEl) ? idEl.GetString() : null;
        if (id is null || !id.StartsWith("MAL-", StringComparison.Ordinal)) yield break;
        var summary = root.TryGetProperty("summary", out var sEl) ? sEl.GetString() : null;
        if (!root.TryGetProperty("affected", out var affected) || affected.ValueKind != JsonValueKind.Array) yield break;

        foreach (var a in affected.EnumerateArray())
        {
            if (!a.TryGetProperty("package", out var pkg)) continue;
            var pkgEco = pkg.TryGetProperty("ecosystem", out var e) ? e.GetString() : null;
            if (!string.Equals(pkgEco, eco, StringComparison.OrdinalIgnoreCase)) continue;

            var purl = pkg.TryGetProperty("purl", out var pEl) ? pEl.GetString() : null;
            if (string.IsNullOrWhiteSpace(purl) && pkg.TryGetProperty("name", out var n) && n.GetString() is { Length: > 0 } name)
                purl = "pkg:" + eco.ToLowerInvariant() + "/" + name;
            var key = BannedComponentMatcher.Key(purl);
            if (key is null) continue;

            // An explicit version list narrows the ban. With no list, the whole package is the problem
            // for a MAL advisory, so every version is banned.
            var versions = a.TryGetProperty("versions", out var vs) && vs.ValueKind == JsonValueKind.Array
                ? vs.EnumerateArray().Select(v => v.GetString()).OfType<string>().ToList()
                : [];
            yield return new MalEntry(key, versions, id, summary);
        }
    }

    private async Task<(int Inserted, int Updated)> UpsertAsync(List<MalEntry> found, CancellationToken ct)
    {
        var existing = await db.BannedComponents
            .Where(b => b.Source == Source)
            .ToDictionaryAsync(b => (b.Purl, b.SourceId), ct);
        int ins = 0, upd = 0;
        var now = DateTimeOffset.UtcNow;
        foreach (var f in found)
        {
            var reason = f.Summary ?? "Reported as a malicious package";
            if (existing.TryGetValue((f.Purl, f.Id), out var row))
            {
                // An admin deactivation (Active = false) sticks across syncs.
                if (row.Versions.SequenceEqual(f.Versions) && row.Reason == reason) continue;
                row.Versions = f.Versions;
                row.Reason = reason;
                row.UpdatedAt = now;
                upd++;
            }
            else
            {
                var added = new BannedComponent
                {
                    Purl = f.Purl, Versions = f.Versions, Kind = BannedComponentKind.Malicious,
                    Source = Source, SourceId = f.Id, Reason = reason,
                };
                db.BannedComponents.Add(added);
                existing[(f.Purl, f.Id)] = added;
                ins++;
            }
        }
        await db.SaveChangesAsync(ct);
        return (ins, upd);
    }
}

public sealed class MaliciousPackageFeedSyncWorker(IServiceProvider sp, ILogger<MaliciousPackageFeedSyncWorker> log) : BackgroundService
{
    private static readonly TimeSpan Interval = TimeSpan.FromHours(24);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken);   // let migration + KEV go first
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                using var scope = sp.CreateScope();
                await scope.ServiceProvider.GetRequiredService<MaliciousPackageFeedSyncService>().SyncAsync(stoppingToken);
            }
            catch (Exception ex) when (!stoppingToken.IsCancellationRequested)
            {
                log.LogError(ex, "malicious-package sync worker tick threw");
            }
            try { await Task.Delay(Interval, stoppingToken); }
            catch (OperationCanceledException) { break; }
        }
    }
}
