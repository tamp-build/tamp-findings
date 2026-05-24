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
}
