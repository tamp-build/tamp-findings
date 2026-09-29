using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Risk;

namespace Tamp.Findings.Domain.Tests;

// The one classifier every banded metric shares (risk score, coverage, tests).
public class BandScaleTests
{
    [Theory]
    [InlineData(2.8, Band.Green)]   // ≤ GreenMax (10)
    [InlineData(10, Band.Green)]
    [InlineData(20, Band.Yellow)]   // ≤ YellowMax (25)
    [InlineData(40, Band.Orange)]   // ≤ OrangeMax (50)
    [InlineData(75, Band.Red)]
    public void Risk_score_is_lower_is_better(double score, Band expected)
    {
        var scale = BandScale.RiskScore(new RiskBands { GreenMax = 10, YellowMax = 25, OrangeMax = 50 });
        Assert.Equal(expected, scale.Classify(score));
    }

    [Theory]
    [InlineData(88.6, Band.Green)]  // ≥ target (80)
    [InlineData(80, Band.Green)]
    [InlineData(75, Band.Yellow)]   // ≥ floor (70), < target
    [InlineData(65, Band.Orange)]   // ≥ floor − width (60), < floor
    [InlineData(55, Band.Red)]
    [InlineData(0, Band.Red)]
    public void Coverage_is_higher_is_better_off_target_and_floor(double pct, Band expected)
    {
        var scale = BandScale.Coverage(targetPercent: 80, floorPercent: 70);
        Assert.Equal(expected, scale.Classify(pct));
    }

    [Fact]
    public void Coverage_bands_slide_with_the_policy()
    {
        // target 90 / floor 80 → green ≥90, yellow 80–90, orange 70–80, red <70.
        var scale = BandScale.Coverage(90, 80);
        Assert.Equal(Band.Green, scale.Classify(92));
        Assert.Equal(Band.Yellow, scale.Classify(85));
        Assert.Equal(Band.Orange, scale.Classify(72));
        Assert.Equal(Band.Red, scale.Classify(69));
    }

    [Fact]
    public void Slug_and_hex_track_the_css_tokens()
    {
        Assert.Equal("green", Band.Green.Slug());
        Assert.Equal("#4fb783", Band.Green.Hex());
        Assert.Equal("#dd5f5f", Band.Red.Hex());
    }
}
