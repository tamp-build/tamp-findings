using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Domain.Tests;

// Matching a package to a paid vendor (TFND-8 / F7.2).
//
// The match decides what appears on a screen that adds up money, so a false
// positive here is a wrong number in somebody's budget and a false negative is
// a renewal nobody saw coming. Both are worth pinning down.
public class PaidComponentTests
{
    private static PaidComponent Entry(
        string prefix = "Telerik.", string? ecosystem = "nuget", bool enabled = true) => new()
    {
        Vendor = "Progress",
        Product = "Telerik UI",
        PackagePrefix = prefix,
        Ecosystem = ecosystem,
        Enabled = enabled,
    };

    [Fact]
    public void It_matches_a_package_by_name()
    {
        Assert.True(Entry().Matches("pkg:nuget/Telerik.UI.for.Blazor@7.1.0", "Telerik.UI.for.Blazor", "nuget"));
    }

    [Fact]
    public void It_matches_case_insensitively()
    {
        // SBOM producers disagree about casing, and NuGet ids are
        // case-insensitive anyway. A registry that only matched the vendor's
        // preferred casing would miss half the emitters.
        Assert.True(Entry().Matches("pkg:nuget/telerik.ui.for.blazor@7.1.0", "telerik.ui.for.blazor", "nuget"));
    }

    [Fact]
    public void It_matches_from_the_purl_when_the_name_is_missing()
    {
        // Some ingests carry a purl and no name. A registry that only worked on
        // well-formed SBOMs would be silent exactly where the data is worst.
        Assert.True(Entry().Matches("pkg:nuget/Telerik.UI.for.Blazor@7.1.0", null, "nuget"));
    }

    [Fact]
    public void It_matches_only_the_name_segment_of_a_purl()
    {
        // "pkg:nuget/..." starts with "pkg:", so a naive prefix test against
        // the whole purl matches nothing — and a substring search anywhere in
        // the string would match a package whose VERSION happened to contain
        // the vendor name.
        var entry = Entry(prefix: "Contoso.");

        Assert.False(entry.Matches("pkg:nuget/Something@1.0-Contoso.build", null, "nuget"));
        Assert.True(entry.Matches("pkg:nuget/Contoso.Widgets@1.0", null, "nuget"));
    }

    [Fact]
    public void A_qualifier_or_subpath_does_not_defeat_the_match()
    {
        Assert.True(Entry().Matches("pkg:nuget/Telerik.UI@7.1.0?repository_url=x", null, "nuget"));
        Assert.True(Entry().Matches("pkg:nuget/Telerik.UI#sub", null, "nuget"));
    }

    [Fact]
    public void It_does_not_match_a_different_ecosystem()
    {
        // Prefixes collide across ecosystems. A bare prefix match everywhere
        // would eventually flag somebody's unrelated package as a paid seat.
        Assert.False(Entry().Matches("pkg:npm/telerik-something@1.0", "telerik-something", "npm"));
    }

    [Fact]
    public void An_entry_with_no_ecosystem_matches_any()
    {
        Assert.True(Entry(ecosystem: null).Matches("pkg:npm/Telerik.Thing@1.0", "Telerik.Thing", "npm"));
    }

    [Fact]
    public void A_disabled_entry_matches_nothing()
    {
        // A shop with a site licence covering a vendor outright does not want
        // every build reporting seats.
        Assert.False(Entry(enabled: false)
            .Matches("pkg:nuget/Telerik.UI.for.Blazor@7.1.0", "Telerik.UI.for.Blazor", "nuget"));
    }

    [Fact]
    public void A_package_that_merely_contains_the_vendor_name_does_not_match()
    {
        // "MyCompany.Telerik.Helpers" is somebody's own wrapper, not a seat.
        Assert.False(Entry().Matches(
            "pkg:nuget/MyCompany.Telerik.Helpers@1.0", "MyCompany.Telerik.Helpers", "nuget"));
    }

    [Fact]
    public void An_empty_package_matches_nothing()
    {
        Assert.False(Entry().Matches(null, null, "nuget"));
        Assert.False(Entry().Matches("", "", "nuget"));
    }

    // ---- The seed ------------------------------------------------------------

    [Fact]
    public void The_seed_names_the_vendors_the_ticket_calls_out()
    {
        var vendors = PaidComponentSeed.All().Select(p => p.Vendor).ToArray();

        Assert.Contains(vendors, v => v.Contains("Progress", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(vendors, v => v.Contains("Syncfusion", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(vendors, v => v.Contains("DevExpress", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void The_seed_ships_no_prices()
    {
        // THE decision on this feature. A list price shipped in a compliance
        // tool becomes a figure quoted in somebody's budget meeting as though
        // we knew what they pay — and list prices are famously not what anyone
        // pays. The operator enters their contract figure.
        Assert.All(PaidComponentSeed.All(), p =>
        {
            Assert.Null(p.AnnualCostPerSeat);
            Assert.Null(p.CostAsOf);
        });
    }

    [Fact]
    public void The_seed_ships_what_can_actually_be_checked()
    {
        // Vendor, product and prefix are verifiable from a package name; the
        // pricing URL is where the operator goes to fill in the rest. All of it
        // is stable in a way a price is not.
        Assert.All(PaidComponentSeed.All(), p =>
        {
            Assert.NotEmpty(p.Vendor);
            Assert.NotEmpty(p.Product);
            Assert.True(p.PackagePrefix.Length >= 2);
            Assert.True(p.IsBuiltIn);
        });
    }

    [Fact]
    public void Seed_ids_are_stable_across_runs()
    {
        // Re-seeding an upgraded instance must update the row it already has
        // rather than adding a second one beside whatever the operator typed
        // into it — which would double-count the vendor on the costs screen.
        var first = PaidComponentSeed.All().Select(p => p.Id).ToArray();
        var second = PaidComponentSeed.All().Select(p => p.Id).ToArray();

        Assert.Equal(first, second);
    }

    [Fact]
    public void No_two_seed_entries_cover_the_same_packages()
    {
        // Two entries matching the same prefix would report one vendor twice on
        // a screen that sums costs.
        var keys = PaidComponentSeed.All()
            .Select(p => $"{p.Ecosystem}|{p.PackagePrefix.ToLowerInvariant()}")
            .ToArray();

        Assert.Equal(keys.Length, keys.Distinct().Count());
    }
}
