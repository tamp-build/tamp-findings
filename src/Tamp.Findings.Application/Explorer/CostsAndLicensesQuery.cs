using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Application.Risk;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Application.Explorer;

/// <summary>
/// The Costs &amp; licences view (TFND-8 / F7.3).
///
/// Two questions on one screen, because they are asked by the same person in
/// the same meeting: what are we obliged to by the licences we depend on, and
/// what are we paying for.
///
/// The honest posture matters more here than anywhere else in this product.
/// Every figure on this screen is an ESTIMATE built from an operator-entered
/// price and a seat count nobody has verified, and it will be read by somebody
/// building a budget. So the totals carry their own caveats, an entry with no
/// price is reported as unpriced rather than as zero, and a stale price says so.
/// A confident wrong number is the failure mode here, not a missing one.
/// </summary>
public sealed class CostsAndLicensesQuery
{
    private readonly FindingsDbContext _db;

    public CostsAndLicensesQuery(FindingsDbContext db) => _db = db;

    /// <summary>
    /// Costs and licences for a project's most recent SBOM per component.
    /// </summary>
    public async Task<CostsAndLicenses> LoadAsync(
        Guid projectId, DateTimeOffset asOf, CancellationToken ct = default)
    {
        // Newest SBOM per component. A project's components are built
        // independently, so "the latest SBOM" is not one snapshot — taking the
        // single newest across the project would silently drop every component
        // that has not built today.
        var snapshots = await (
            from s in _db.SbomSnapshots.AsNoTracking()
            join cv in _db.ComponentVersions.AsNoTracking() on s.ComponentVersionId equals cv.Id
            join c in _db.Components.AsNoTracking() on cv.ComponentId equals c.Id
            where c.ProjectId == projectId
            select new { s.Id, ComponentId = c.Id, ComponentName = c.Name, cv.CreatedAt })
            .ToArrayAsync(ct);

        var latest = snapshots
            .GroupBy(s => s.ComponentId)
            .Select(g => g.OrderByDescending(s => s.CreatedAt).First())
            .ToArray();

        var snapshotIds = latest.Select(s => s.Id).ToArray();
        var componentOf = latest.ToDictionary(s => s.Id, s => s.ComponentName);

        var packages = await _db.SbomComponents.AsNoTracking()
            .Where(p => snapshotIds.Contains(p.SbomSnapshotId))
            .Select(p => new
            {
                p.SbomSnapshotId, p.Purl, p.Name, p.Version, p.License, p.LatestVersion,
            })
            .ToArrayAsync(ct);

        var registry = await _db.PaidComponents.AsNoTracking().ToArrayAsync(ct);

        // ---- Licences --------------------------------------------------------

        // Distinct by purl before tallying. The same package appearing in three
        // components is one licence obligation, not three, and a tally that
        // counted it three times would make a single AGPL dependency look like
        // an epidemic.
        var distinct = packages
            .GroupBy(p => p.Purl, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.First())
            .ToArray();

        var licences = distinct
            .GroupBy(p => LicensePolicy.Classify(p.License))
            .ToDictionary(g => g.Key, g => g.Count());

        var obligations = distinct
            .Select(p => new { p, Tier = LicensePolicy.Classify(p.License) })
            .Where(x => x.Tier is LicensePolicy.Tier.Denied
                            or LicensePolicy.Tier.StrongCopyleft
                            or LicensePolicy.Tier.Unknown)
            .Select(x => new LicenceObligation(
                x.p.Purl, x.p.Name, x.p.Version, x.p.License, x.Tier,
                componentOf.TryGetValue(x.p.SbomSnapshotId, out var name) ? name : "(unknown)"))
            // Denied first, then strong copyleft, then unknown. Unknown is last
            // not because it is least serious — it is the one nobody can rule
            // out — but because it is usually the longest list, and burying the
            // denied rows under it is how a denied row goes unread.
            .OrderByDescending(o => o.Tier == LicensePolicy.Tier.Denied)
            .ThenByDescending(o => o.Tier == LicensePolicy.Tier.StrongCopyleft)
            .ThenBy(o => o.Name, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        // ---- Paid components -------------------------------------------------

        var paid = new List<PaidUsage>();

        foreach (var entry in registry)
        {
            var matches = packages
                .Where(p => entry.Matches(p.Purl, p.Name, EcosystemOf(p.Purl)))
                .ToArray();

            if (matches.Length == 0) continue;

            var components = matches
                .Select(m => componentOf.TryGetValue(m.SbomSnapshotId, out var name) ? name : "(unknown)")
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(n => n, StringComparer.OrdinalIgnoreCase)
                .ToArray();

            paid.Add(new PaidUsage(
                entry.Id, entry.Vendor, entry.Product, entry.LicenseModel, entry.PricingUrl,
                entry.AnnualCostPerSeat, entry.Currency, entry.CostAsOf,
                // A year is generous. Vendors reprice annually at most, and
                // flagging a six-month-old figure would train people to ignore
                // the flag.
                Stale: entry.CostAsOf is null || (asOf - entry.CostAsOf.Value).TotalDays > 365,
                entry.SupportEndsAt,
                entry.SupportEndsAt is { } ends && ends <= asOf,
                entry.Notes,
                matches
                    .GroupBy(m => m.Purl, StringComparer.OrdinalIgnoreCase)
                    .Select(g => g.First())
                    .Select(m => new PaidPackage(m.Purl, m.Name, m.Version, m.LatestVersion))
                    .OrderBy(m => m.Name, StringComparer.OrdinalIgnoreCase)
                    .ToArray(),
                components));
        }

        var ordered = paid
            // Priced first: those are the rows that add up to a number, and the
            // unpriced ones are a call to action rather than part of the total.
            .OrderByDescending(p => p.AnnualCostPerSeat is not null)
            .ThenByDescending(p => p.AnnualCostPerSeat ?? 0)
            .ThenBy(p => p.Vendor, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        return new CostsAndLicenses(
            ordered,
            obligations,
            licences,
            distinct.Length,
            // Currencies are NOT summed across. Adding USD to EUR because both
            // are numbers is the kind of error a budget screen must not make,
            // so a mixed registry reports per currency and the screen says so.
            ordered
                .Where(p => p.AnnualCostPerSeat is not null)
                .GroupBy(p => p.Currency, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(g => g.Key, g => g.Sum(p => p.AnnualCostPerSeat!.Value),
                    StringComparer.OrdinalIgnoreCase),
            ordered.Count(p => p.AnnualCostPerSeat is null));
    }

    /// <summary>
    /// The ecosystem token out of a purl — "pkg:nuget/Foo@1.0" is "nuget".
    /// </summary>
    internal static string? EcosystemOf(string? purl)
    {
        if (purl is not { Length: > 0 }) return null;

        var start = purl.StartsWith("pkg:", StringComparison.OrdinalIgnoreCase) ? 4 : 0;
        var slash = purl.IndexOf('/', start);

        return slash <= start ? null : purl[start..slash];
    }
}

/// <summary>
/// Everything the screen renders.
///
/// <paramref name="AnnualPerSeatByCurrency"/> is per developer seat, not a
/// total bill — this product does not know the team size, and multiplying by a
/// number it guessed would turn an estimate into a fabrication.
/// </summary>
public sealed record CostsAndLicenses(
    IReadOnlyList<PaidUsage> Paid,
    IReadOnlyList<LicenceObligation> Obligations,
    IReadOnlyDictionary<LicensePolicy.Tier, int> LicenceTiers,
    int DistinctPackages,
    IReadOnlyDictionary<string, decimal> AnnualPerSeatByCurrency,
    int UnpricedProducts);

public sealed record PaidUsage(
    Guid RegistryId,
    string Vendor,
    string Product,
    string? LicenseModel,
    string? PricingUrl,
    decimal? AnnualCostPerSeat,
    string Currency,
    DateTimeOffset? CostAsOf,
    bool Stale,
    DateTimeOffset? SupportEndsAt,
    bool SupportEnded,
    string? Notes,
    IReadOnlyList<PaidPackage> Packages,
    IReadOnlyList<string> Components);

public sealed record PaidPackage(string Purl, string Name, string Version, string? LatestVersion);

public sealed record LicenceObligation(
    string Purl, string Name, string Version, string? License,
    LicensePolicy.Tier Tier, string Component);
