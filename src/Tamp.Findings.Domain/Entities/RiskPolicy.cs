using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Domain.Entities;

// Configurable risk-scoring policy. Stored as a row per named policy;
// the per-category weights/caps live in the typed Config blob (jsonb).
// A Client or Project can point at a specific policy; otherwise the
// IsDefault row applies.
public sealed class RiskPolicy
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public required string Name { get; set; }
    public string? Description { get; set; }
    // Exactly one row in the table should be marked IsDefault. Used when
    // a Client/Project has no per-scope policy assignment. Flipping the
    // default is its own admin endpoint that ensures the previous default
    // is cleared atomically.
    public bool IsDefault { get; set; }
    // Marks the system-seeded policy. Today this is informational — the
    // seed policy is editable like any other. Surface in the UI so the
    // admin knows which row shipped with the app vs which they authored.
    public bool IsSeeded { get; set; }
    public required RiskPolicyConfig Config { get; set; }
    public Guid? CreatedByUserId { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;
}

// Typed config the RiskScorer evaluates against an aggregates response.
// Stored as jsonb (Npgsql dynamic JSON is enabled in
// ServiceCollectionExtensions). SchemaVersion lets future shape changes
// migrate forward — the scorer fails fast on unknown versions.
public sealed class RiskPolicyConfig
{
    public int SchemaVersion { get; set; } = 1;
    public RiskBands Bands { get; set; } = new();
    public Dictionary<string, RiskCategoryConfig> Categories { get; set; } = new();
    // Optional per-scanner severity ceilings — keyed by ScannerKind name
    // ("ESLint", "Roslyn", etc.). When set, findings from that scanner
    // are downgraded to at most the ceiling severity BEFORE scoring.
    // Empty = no scanner is downweighted (every finding scores at its
    // ingested severity). Surfaces in the policy editor as one dropdown
    // per scanner.
    public Dictionary<string, ScannerOverride> ScannerOverrides { get; set; } = new();

    // TFND-10 / F9.3: the licence allow- and denylist, as POLICY rather than
    // as a table compiled into the product.
    //
    // The built-in classification stays — it is a reasonable default and most
    // adopters will never touch it — but it is now the FALLBACK. Which licences
    // an organisation can live with is a legal position, not a fact about
    // software, and two adopters can hold opposite ones about the same licence
    // and both be right. A hardcoded table quietly makes that decision for
    // them.
    public LicenseRules Licenses { get; set; } = new();

    // TFND-10 / F9.3: paid-component approval.
    public PaidComponentRules PaidComponents { get; set; } = new();
}

/// <summary>
/// Licences this policy explicitly permits or refuses (F9.3).
///
/// Layered OVER the built-in classification rather than replacing it, so an
/// adopter states the handful they care about instead of re-entering the SPDX
/// list. Deny wins over Allow: a licence named in both is a mistake, and the
/// safe reading of a mistake on this particular question is the strict one.
/// </summary>
public sealed class LicenseRules
{
    /// <summary>SPDX ids to treat as permissive whatever the built-in table says.</summary>
    public List<string> Allow { get; set; } = new();

    /// <summary>SPDX ids to treat as denied whatever the built-in table says.</summary>
    public List<string> Deny { get; set; } = new();

    /// <summary>
    /// Treat a licence nobody could classify as denied rather than as unknown.
    ///
    /// Off by default, because on a real SBOM the unknown pile is large and
    /// mostly benign — turning it on would make every policy fail on day one,
    /// and a policy that always fails is a policy people learn to ignore. On,
    /// for an organisation that genuinely cannot ship an unidentified licence.
    /// </summary>
    public bool DenyUnknown { get; set; }
}

/// <summary>
/// Whether paid components need approving, and which are approved (F9.3).
///
/// The registry (TFND-8) knows which packages cost money. This is the separate
/// question of whether THIS organisation has agreed to that spend — a licence
/// somebody has to buy, appearing in a build nobody approved it for, is a
/// procurement problem before it is a security one.
/// </summary>
public sealed class PaidComponentRules
{
    /// <summary>
    /// Off by default. On, any matched paid vendor not in
    /// <see cref="ApprovedVendors"/> is a policy violation.
    /// </summary>
    public bool RequireApproval { get; set; }

    /// <summary>
    /// Vendor names, matched case-insensitively against the registry.
    ///
    /// Vendor rather than package, because these vendors ship dozens of
    /// packages under one subscription — approving the spend is a decision
    /// about the vendor, and an approval list of package names would be out of
    /// date by the next release.
    /// </summary>
    public List<string> ApprovedVendors { get; set; } = new();
}

public sealed class ScannerOverride
{
    // null/absent = use the finding's ingested severity (no override).
    // Set to "Low" to cap every High/Critical/Medium ESLint finding at
    // Low for scoring purposes — display data stays at the original
    // severity, only the score is affected.
    public Severity? SeverityCeiling { get; set; }
}

// Score bands. green: 0..GreenMax, yellow: GreenMax..YellowMax,
// orange: YellowMax..OrangeMax, red: OrangeMax..100.
public sealed class RiskBands
{
    public double GreenMax { get; set; } = 10;
    public double YellowMax { get; set; } = 25;
    public double OrangeMax { get; set; } = 50;
}

// One row per category in the formula. Enabled=false zeros it without
// rewriting Weights. Max is the upper bound of points this category
// contributes to the 0..100 score. Weights is free-form so different
// categories can use different keys ({ "critical", "high", ... } for
// CVEs, { "targetPercent" } for Coverage, etc.) — the scorer reads
// the keys it knows for each named category.
public sealed class RiskCategoryConfig
{
    public bool Enabled { get; set; } = true;
    public double Max { get; set; }
    public Dictionary<string, double> Weights { get; set; } = new();
}

// Canonical category keys used by the scorer + seed.
public static class RiskCategoryNames
{
    public const string Cve = "cve";
    public const string Secrets = "secrets";
    public const string SastSevere = "sastSevere";
    public const string IacSevere = "iacSevere";
    public const string Coverage = "coverage";
    public const string SbomStaleness = "sbomStaleness";
    public const string Tests = "tests";
    public const string License = "license";
    public const string SastLow = "sastLow";
    public const string MissingScanners = "missingScanners";
    // DAST — dynamic scan of a deployed target. Split severe/low on the
    // same lines as SAST so an admin can weight runtime-confirmed
    // findings independently of static ones.
    public const string DastSevere = "dastSevere";
    public const string DastLow = "dastLow";
    // TFND-33 … TFND-37 — design and maintainability findings: OpenAPI lint,
    // breaking-change detection, mutation testing, architecture rules.
    //
    // Its OWN category rather than folded into sastLow, because the two answer
    // different questions and an admin should be able to weight them
    // separately. A team shipping an internal service may not care about
    // OpenAPI lint at all; a team shipping a public API cares a great deal.
    public const string Quality = "quality";
    // TFND-27 — Section 508 / WCAG 2.1 AA conformance.
    //
    // Its own category for the same reason it is its own scanner set: the
    // audience is UX and compliance rather than security triage, and an admin
    // shipping a headless service should be able to zero it without touching
    // anything else.
    public const string Accessibility = "accessibility";
}
