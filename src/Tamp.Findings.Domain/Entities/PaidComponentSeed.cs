namespace Tamp.Findings.Domain.Entities;

/// <summary>
/// The vendors this product ships knowing about (TFND-8 / F7.2).
///
/// What is seeded here is only what is STABLE AND CHECKABLE: who the vendor is,
/// which package prefix belongs to them, how they license, and where their
/// pricing page is. All of that can be verified from a package name and a URL,
/// and none of it goes stale in a way that misleads.
///
/// What is NOT seeded is the price. See <see cref="PaidComponent.AnnualCostPerSeat"/>
/// — a list price shipped in a compliance tool becomes a number quoted in
/// somebody's budget meeting as though we knew what they pay, and we do not.
/// The operator enters their contract figure; the screen asks them to, and says
/// why it is blank.
///
/// The ticket names Telerik, Syncfusion and DevExpress explicitly. The rest are
/// the ones that show up in the same SBOMs and cost money in the same way.
/// </summary>
public static class PaidComponentSeed
{
    public static IReadOnlyList<PaidComponent> All() =>
    [
        Nuget("Progress", "Telerik UI", "Telerik.",
            "per developer", "https://www.telerik.com/purchase.aspx",
            "Covers Telerik UI for Blazor / WinForms / WPF / ASP.NET and Kendo. "
            + "One subscription spans the suite, so seats are counted per developer, not per package."),

        Npm("Progress", "Kendo UI", "@progress/kendo",
            "per developer", "https://www.telerik.com/kendo-ui/pricing",
            "Same subscription as Telerik UI on the .NET side — do not count a developer twice "
            + "if both appear in one solution."),

        Nuget("Syncfusion", "Essential Studio", "Syncfusion.",
            "per developer", "https://www.syncfusion.com/sales/teamlicense",
            "Syncfusion also offers a free community licence below a revenue and headcount "
            + "threshold. A match here is not proof of a bill."),

        Nuget("DevExpress", "DevExpress Universal", "DevExpress.",
            "per developer", "https://www.devexpress.com/buy/net/",
            "Subscriptions are per developer and tiered by product set; the tier is not "
            + "derivable from the packages present."),

        Nuget("Infragistics", "Ultimate UI", "Infragistics.",
            "per developer", "https://www.infragistics.com/how-to-buy/product-pricing", null),

        Nuget("ComponentOne (MESCIUS)", "ComponentOne Studio", "C1.",
            "per developer", "https://developer.mescius.com/componentone/pricing", null),

        Nuget("Aspose", "Aspose.NET", "Aspose.",
            "per developer", "https://purchase.aspose.com/pricing",
            "Licensed per product family — Words, Cells, PDF and so on are separate buys, "
            + "so the package list matters here more than for a suite vendor."),

        Nuget("IronSoftware", "Iron Suite", "IronPdf",
            "per developer", "https://ironpdf.com/licensing/", null),

        Nuget("GrapeCity (MESCIUS)", "Documents", "GrapeCity.",
            "per developer", "https://developer.mescius.com/document-solutions", null),

        Nuget("Redgate", "SQL Toolbelt", "RedGate.",
            "per user", "https://www.red-gate.com/products/", null),

        Nuget("PostSharp (SharpCrafters)", "PostSharp", "PostSharp",
            "per developer", "https://www.postsharp.net/pricing",
            "Has a free tier limited by the number of enhanced types, so a match is not "
            + "necessarily a paid seat."),

        Nuget("JetBrains", "dotUltimate", "JetBrains.",
            "per developer", "https://www.jetbrains.com/dotnet/buy/",
            "Includes the ReSharper command-line tools this product ingests findings from — "
            + "a build agent using them is inside somebody's licence."),

        Nuget("Stimulsoft", "Reports.NET", "Stimulsoft.",
            "per developer", "https://www.stimulsoft.com/en/prices", null),

        Nuget("Devart", "dotConnect", "Devart.",
            "per developer", "https://www.devart.com/dotconnect/", null),

        Nuget("Rebex", "Rebex Total Pack", "Rebex.",
            "per developer", "https://www.rebex.net/total-pack/", null),
    ];

    private static PaidComponent Nuget(
        string vendor, string product, string prefix, string model, string? pricing, string? notes) =>
        Make(vendor, product, prefix, "nuget", model, pricing, notes);

    private static PaidComponent Npm(
        string vendor, string product, string prefix, string model, string? pricing, string? notes) =>
        Make(vendor, product, prefix, "npm", model, pricing, notes);

    private static PaidComponent Make(
        string vendor, string product, string prefix, string ecosystem,
        string model, string? pricing, string? notes) => new()
    {
        // Deterministic id from vendor + prefix, so re-seeding an existing
        // instance updates the row it already has rather than adding a second
        // one next to whatever the operator edited into it.
        Id = DeterministicId(vendor, prefix),
        Vendor = vendor,
        Product = product,
        PackagePrefix = prefix,
        Ecosystem = ecosystem,
        LicenseModel = model,
        PricingUrl = pricing,
        Notes = notes,
        IsBuiltIn = true,
    };

    /// <summary>
    /// A stable id for a seed row.
    ///
    /// MD5 rather than a GUID literal per row: the point is that the same
    /// vendor and prefix always produce the same id, so seeding is idempotent
    /// across upgrades. Not a security decision — nothing here is secret and
    /// nothing authenticates against it.
    /// </summary>
    private static Guid DeterministicId(string vendor, string prefix) =>
        new(System.Security.Cryptography.MD5.HashData(
            System.Text.Encoding.UTF8.GetBytes($"tamp.findings.paid-component:{vendor}:{prefix}")));
}
