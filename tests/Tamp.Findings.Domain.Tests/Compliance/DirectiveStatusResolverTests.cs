using Tamp.Findings.Domain.Compliance;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Domain.Tests;

// The point-in-time engine (ADR 0011 §4, §7). A compliance claim is only meaningful
// against the set in force on the evaluation date, and a rescind is forward-dated, not
// retroactive — these pin exactly that.
public class DirectiveStatusResolverTests
{
    private static DirectiveStatusChange Change(DirectiveStatus s, string effective, string? recorded = null) =>
        new()
        {
            Status = s,
            EffectiveDate = DateTimeOffset.Parse(effective),
            RecordedAt = DateTimeOffset.Parse(recorded ?? effective),
        };

    private static DateTimeOffset On(string d) => DateTimeOffset.Parse(d);

    [Fact]
    public void No_change_on_or_before_the_date_is_null()
    {
        var changes = new[] { Change(DirectiveStatus.Active, "2025-01-16") };
        Assert.Null(DirectiveStatusResolver.StatusAsOf(changes, On("2025-01-01")));
        Assert.False(DirectiveStatusResolver.IsInForceAsOf(changes, On("2025-01-01")));
    }

    [Fact]
    public void Latest_change_on_or_before_the_date_wins()
    {
        // Active 2025-01-16, then rescinded 2025-06-06 (the EO 14306-over-14144 case).
        var changes = new[]
        {
            Change(DirectiveStatus.Active, "2025-01-16"),
            Change(DirectiveStatus.Rescinded, "2025-06-06"),
        };

        // Before the rescind: in force.
        Assert.Equal(DirectiveStatus.Active, DirectiveStatusResolver.StatusAsOf(changes, On("2025-05-01")));
        Assert.True(DirectiveStatusResolver.IsInForceAsOf(changes, On("2025-05-01")));

        // On/after the rescind: no longer in force — but the history before it stands.
        Assert.Equal(DirectiveStatus.Rescinded, DirectiveStatusResolver.StatusAsOf(changes, On("2025-06-06")));
        Assert.False(DirectiveStatusResolver.IsInForceAsOf(changes, On("2025-07-01")));
    }

    [Fact]
    public void Rescind_is_forward_dated_not_retroactive()
    {
        // A system evaluated as-of 2025-05-01 was non-compliant with a directive that
        // was later rescinded; that historical fact must not be erased by the rescind.
        var changes = new[]
        {
            Change(DirectiveStatus.Active, "2025-01-16"),
            Change(DirectiveStatus.Rescinded, "2025-06-06"),
        };
        Assert.True(DirectiveStatusResolver.IsInForceAsOf(changes, On("2025-05-01")));  // was in force then
        Assert.False(DirectiveStatusResolver.IsInForceAsOf(changes, On("2025-09-01"))); // dormant now
    }

    [Fact]
    public void A_later_recorded_correction_at_the_same_effective_date_wins()
    {
        var changes = new[]
        {
            Change(DirectiveStatus.Active, "2025-01-16", recorded: "2025-01-16"),
            Change(DirectiveStatus.Superseded, "2025-01-16", recorded: "2025-02-01"), // correction
        };
        Assert.Equal(DirectiveStatus.Superseded, DirectiveStatusResolver.StatusAsOf(changes, On("2025-03-01")));
    }

    [Fact]
    public void Empty_history_is_null()
        => Assert.Null(DirectiveStatusResolver.StatusAsOf([], On("2025-01-01")));
}
