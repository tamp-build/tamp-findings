namespace Tamp.Findings.Domain.Entities;

/// <summary>
/// A commercial component this instance knows costs money (TFND-8 / F7.2).
///
/// The gap it closes: an SBOM says <c>pkg:nuget/Telerik.UI.for.Blazor@7.1.0</c>
/// and a licence field that is either blank or a vendor EULA name. Nothing in
/// that tells anyone this line item is a paid seat, that the seat renews, or
/// that the renewal is a budget conversation somebody should be having in
/// October rather than in January.
///
/// Instance-scoped rather than per-project, because "Telerik is a paid product"
/// is a fact about the world, not about a tenant. What each tenant PAYS is a
/// different question, and the per-project view answers it by counting seats
/// against this registry.
/// </summary>
public sealed class PaidComponent
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public required string Vendor { get; set; }
    public required string Product { get; set; }

    /// <summary>
    /// Package-name prefix this matches, case-insensitively — "Telerik.",
    /// "Syncfusion.", "DevExpress.".
    ///
    /// A prefix rather than an exact purl because these vendors ship dozens to
    /// hundreds of packages under one licence, the set changes every release,
    /// and enumerating them would mean the registry is wrong the moment a
    /// vendor adds a package. A prefix is the shape of the actual licensing
    /// boundary.
    /// </summary>
    public required string PackagePrefix { get; set; }

    /// <summary>
    /// Ecosystem the prefix applies to ("nuget", "npm"), or null for any.
    ///
    /// Matters because prefixes collide across ecosystems: npm's
    /// <c>@progress/kendo-*</c> and NuGet's <c>Telerik.*</c> are the same
    /// vendor and often the same licence, but a bare prefix match across every
    /// ecosystem would eventually flag somebody's unrelated package.
    /// </summary>
    public string? Ecosystem { get; set; }

    /// <summary>
    /// Approximate annual cost per developer seat, in
    /// <see cref="Currency"/>.
    ///
    /// SHIPS NULL, deliberately, and the UI says why. A seeded list price would
    /// be a number this product asserts about somebody's budget while having no
    /// idea what they actually negotiated — and list prices are famously not
    /// what anyone pays. Once it is on a screen it gets quoted in a planning
    /// meeting as though this tool knew.
    ///
    /// The operator enters what their contract says. That number is both more
    /// useful and the only one that is true.
    /// </summary>
    public decimal? AnnualCostPerSeat { get; set; }

    public string Currency { get; set; } = "USD";

    /// <summary>
    /// When <see cref="AnnualCostPerSeat"/> was last confirmed.
    ///
    /// A cost with no date is a cost nobody can decide whether to trust. Shown
    /// next to the figure and flagged once it is stale, because a renewal
    /// estimate built on a three-year-old number is worse than no estimate.
    /// </summary>
    public DateTimeOffset? CostAsOf { get; set; }

    /// <summary>How the vendor licenses it — "per developer", "per app", "site".</summary>
    public string? LicenseModel { get; set; }

    /// <summary>The vendor's own pricing page, so the figure can be checked.</summary>
    public string? PricingUrl { get; set; }

    /// <summary>
    /// Approximate end of support, where the vendor states one.
    ///
    /// Null far more often than not: most of these vendors publish a support
    /// window per major version rather than a date, and inventing one would be
    /// a guess presented as a deadline.
    /// </summary>
    public DateTimeOffset? SupportEndsAt { get; set; }

    public string? Notes { get; set; }

    /// <summary>
    /// Shipped with the product rather than added by the operator.
    ///
    /// Seeded rows can be edited and disabled but are recognisable as ours, so
    /// an upgrade can add vendors without overwriting what an operator entered
    /// about their own contracts.
    /// </summary>
    public bool IsBuiltIn { get; set; }

    /// <summary>
    /// Off means "do not flag matches for this". A shop that has a site licence
    /// covering a vendor outright does not want every build reporting seats.
    /// </summary>
    public bool Enabled { get; set; } = true;

    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;

    /// <summary>Does this package fall under this entry?</summary>
    public bool Matches(string? purl, string? name, string? ecosystem)
    {
        if (!Enabled) return false;

        if (Ecosystem is { Length: > 0 } required
            && !string.Equals(required, ecosystem, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        // Name first: it is what the prefix is written against. The purl is
        // checked too because some ingests carry a purl and no name, and a
        // registry that only worked for well-formed SBOMs would be silent
        // exactly where the data is worst.
        return Starts(name) || PurlNameStarts(purl);
    }

    private bool Starts(string? value) =>
        value is { Length: > 0 } && value.StartsWith(PackagePrefix, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Match the NAME segment of a purl, not the whole string.
    ///
    /// "pkg:nuget/Telerik.UI@1.0" starts with "pkg:", so a naive prefix test
    /// against the purl matches nothing — and a test that searched anywhere in
    /// the string would match a package whose version or qualifier happened to
    /// contain the vendor name.
    /// </summary>
    private bool PurlNameStarts(string? purl)
    {
        if (purl is not { Length: > 0 }) return false;

        var slash = purl.IndexOf('/');
        if (slash < 0 || slash == purl.Length - 1) return false;

        var rest = purl[(slash + 1)..];
        var end = rest.IndexOfAny(['@', '?', '#']);
        if (end >= 0) rest = rest[..end];

        return rest.StartsWith(PackagePrefix, StringComparison.OrdinalIgnoreCase);
    }
}
