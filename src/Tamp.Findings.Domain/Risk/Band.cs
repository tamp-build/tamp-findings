using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Domain.Risk;

/// <summary>The four health bands, shared by every metric that colours a value.</summary>
public enum Band { Green, Yellow, Orange, Red }

public static class BandExtensions
{
    /// <summary>The CSS/token slug — matches <c>--color-band-{slug}</c> and the score-band strings.</summary>
    public static string Slug(this Band band) => band switch
    {
        Band.Green => "green",
        Band.Yellow => "yellow",
        Band.Orange => "orange",
        _ => "red",
    };

    /// <summary>
    /// The canonical band hex, kept in lockstep with the <c>--color-band-*</c> CSS tokens.
    /// The single source the SVG badge (which has no stylesheet) shares with the app.
    /// </summary>
    public static string Hex(this Band band) => band switch
    {
        Band.Green => "#4fb783",
        Band.Yellow => "#d4bb4a",
        Band.Orange => "#d68f42",
        _ => "#dd5f5f",
    };

    /// <summary>Parse a band slug back to the enum (unknown → Red, the safe/worst band). Lets a
    /// consumer that only has the slug — e.g. the SVG badge from the shared status summary — resolve
    /// the canonical <see cref="Hex"/> without re-declaring colours.</summary>
    public static Band FromSlug(string? slug) => slug switch
    {
        "green" => Band.Green,
        "yellow" => Band.Yellow,
        "orange" => Band.Orange,
        _ => Band.Red,
    };
}

/// <summary>
/// One classifier for every banded number in the product — the overall risk score, coverage %,
/// test pass rate, and anything else that wants green / yellow / orange / red.
///
/// Three boundaries and a direction, nothing metric-specific. <c>HigherIsBetter = false</c> is
/// the risk-score orientation (a LOW number is good); <c>true</c> is coverage / tests (a HIGH
/// number is good). Every metric expresses its policy as one of the factories below, so a
/// threshold lives in exactly one place and the colour of a value cannot drift between the
/// sidebar, the badge and the explorer.
/// </summary>
public sealed record BandScale(double GoodAt, double WarnAt, double BadAt, bool HigherIsBetter)
{
    public Band Classify(double value) => HigherIsBetter
        ? value >= GoodAt ? Band.Green
          : value >= WarnAt ? Band.Yellow
          : value >= BadAt ? Band.Orange
          : Band.Red
        : value <= GoodAt ? Band.Green
          : value <= WarnAt ? Band.Yellow
          : value <= BadAt ? Band.Orange
          : Band.Red;

    /// <summary>The colour slug for a value, ready for <c>--color-band-{slug}</c>.</summary>
    public string SlugFor(double value) => Classify(value).Slug();

    /// <summary>
    /// The overall risk score (0..100), LOWER is better. Reads the project's own band boundaries,
    /// so this is exactly the classification <c>RiskScorer</c> applies to the score.
    /// </summary>
    public static BandScale RiskScore(RiskBands bands) =>
        new(bands.GreenMax, bands.YellowMax, bands.OrangeMax, HigherIsBetter: false);

    /// <summary>
    /// Coverage %, HIGHER is better, derived from the project's own two anchors: the score TARGET
    /// (green at or above it, zero penalty) and the gate FLOOR (yellow down to it, still shippable).
    /// Orange is one band-width below the floor — failing the gate but recoverable — and red is
    /// below that or unmeasured. No magic numbers: move the target/floor and the bands slide.
    /// </summary>
    public static BandScale Coverage(double targetPercent, double floorPercent)
    {
        var width = Math.Max(1, targetPercent - floorPercent);
        return new(targetPercent, floorPercent, floorPercent - width, HigherIsBetter: true);
    }

    /// <summary>A generic higher-is-better percentage (e.g. test pass rate), with sane defaults.</summary>
    public static BandScale Percent(double green = 90, double yellow = 75, double orange = 60) =>
        new(green, yellow, orange, HigherIsBetter: true);
}
