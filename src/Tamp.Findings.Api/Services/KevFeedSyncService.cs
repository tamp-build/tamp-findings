using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Api.Services;

// Fetches the CISA Known Exploited Vulnerabilities catalog and upserts
// it into our local cache. The feed is one JSON file refreshed by CISA
// roughly weekly; we sync on startup and then on a daily timer. Caller
// (BackgroundService) drives the loop; this service has no schedule of
// its own so tests can call SyncAsync() deterministically.
public sealed class KevFeedSyncService(
    IHttpClientFactory httpClientFactory,
    FindingsDbContext db,
    ILogger<KevFeedSyncService> log)
{
    public const string FeedUrl = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

    public async Task<KevSyncResult> SyncAsync(CancellationToken ct = default)
    {
        var http = httpClientFactory.CreateClient("registries");
        http.Timeout = TimeSpan.FromSeconds(60);

        KevCatalogDto? catalog;
        try
        {
            catalog = await http.GetFromJsonAsync<KevCatalogDto>(FeedUrl, ct);
        }
        catch (Exception ex)
        {
            log.LogWarning(ex, "KEV feed fetch failed; keeping existing cache");
            return new KevSyncResult(false, 0, 0, ex.Message);
        }
        if (catalog?.Vulnerabilities is null || catalog.Vulnerabilities.Count == 0)
        {
            log.LogWarning("KEV feed returned no vulnerabilities");
            return new KevSyncResult(false, 0, 0, "feed empty");
        }

        // Build a lookup of existing rows once; upsert in a single pass.
        // The feed is ~1k rows today, all-in-memory is fine.
        var existing = await db.KevAdvisories.ToDictionaryAsync(x => x.CveId, ct);
        var now = DateTimeOffset.UtcNow;
        var inserted = 0;
        var updated = 0;
        foreach (var v in catalog.Vulnerabilities)
        {
            if (string.IsNullOrWhiteSpace(v.CveId)) continue;
            var dateAdded = ParseDateOnly(v.DateAdded);
            var dueDate = ParseDateOnly(v.DueDate);
            var ransomware = string.Equals(v.KnownRansomwareCampaignUse, "Known", StringComparison.OrdinalIgnoreCase);

            if (existing.TryGetValue(v.CveId, out var row))
            {
                row.VendorProject = v.VendorProject;
                row.Product = v.Product;
                row.VulnerabilityName = v.VulnerabilityName;
                row.DateAdded = dateAdded;
                row.DueDate = dueDate;
                row.ShortDescription = v.ShortDescription;
                row.RequiredAction = v.RequiredAction;
                row.KnownRansomwareCampaignUse = ransomware;
                row.Notes = v.Notes;
                row.LastSyncedAt = now;
                updated++;
            }
            else
            {
                db.KevAdvisories.Add(new KevAdvisory
                {
                    CveId = v.CveId,
                    VendorProject = v.VendorProject,
                    Product = v.Product,
                    VulnerabilityName = v.VulnerabilityName,
                    DateAdded = dateAdded,
                    DueDate = dueDate,
                    ShortDescription = v.ShortDescription,
                    RequiredAction = v.RequiredAction,
                    KnownRansomwareCampaignUse = ransomware,
                    Notes = v.Notes,
                    LastSyncedAt = now,
                });
                inserted++;
            }
        }
        // We deliberately do NOT delete rows missing from the feed.
        // CISA occasionally retires entries (rare but it happens); a
        // dropped row likely means the catalog entry was reclassified,
        // not "this CVE is no longer dangerous." Keeping the historic
        // row lets the dashboard explain the disappearance.
        await db.SaveChangesAsync(ct);
        log.LogInformation("KEV sync OK — {Inserted} inserted, {Updated} updated, total now {Total}",
            inserted, updated, existing.Count + inserted);
        return new KevSyncResult(true, inserted, updated, null);
    }

    private static DateOnly ParseDateOnly(string? s) =>
        DateOnly.TryParse(s, out var d) ? d : DateOnly.MinValue;
}

public sealed record KevSyncResult(bool Success, int Inserted, int Updated, string? Error);

// Mirrors the relevant slice of CISA's KEV catalog JSON. Field names
// are case-insensitive in System.Text.Json by default; the casing
// here matches the published feed.
internal sealed class KevCatalogDto
{
    public List<KevCatalogEntryDto>? Vulnerabilities { get; set; }
}

internal sealed class KevCatalogEntryDto
{
    public string? CveId { get; set; }
    public string? VendorProject { get; set; }
    public string? Product { get; set; }
    public string? VulnerabilityName { get; set; }
    public string? DateAdded { get; set; }
    public string? ShortDescription { get; set; }
    public string? RequiredAction { get; set; }
    public string? DueDate { get; set; }
    public string? KnownRansomwareCampaignUse { get; set; }
    public string? Notes { get; set; }
}

// Daily refresh + startup sync. Hosted in DI as a singleton-ish
// BackgroundService — each tick creates its own scope so we can use
// the scoped FindingsDbContext + KevFeedSyncService.
public sealed class KevFeedSyncWorker(
    IServiceProvider sp,
    ILogger<KevFeedSyncWorker> log) : BackgroundService
{
    private static readonly TimeSpan SyncInterval = TimeSpan.FromHours(24);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Slight stagger so we don't fight migration on first boot.
        await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken);
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                using var scope = sp.CreateScope();
                var svc = scope.ServiceProvider.GetRequiredService<KevFeedSyncService>();
                await svc.SyncAsync(stoppingToken);
            }
            catch (Exception ex) when (!stoppingToken.IsCancellationRequested)
            {
                log.LogError(ex, "KEV sync worker tick threw");
            }
            try { await Task.Delay(SyncInterval, stoppingToken); }
            catch (OperationCanceledException) { break; }
        }
    }
}
