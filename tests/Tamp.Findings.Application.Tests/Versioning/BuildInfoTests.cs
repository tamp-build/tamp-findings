using Tamp.Findings.Application.Versioning;

namespace Tamp.Findings.Application.Tests.Versioning;

// TFND-267: the version an instance reports is parsed from what the build stamped into the assembly.
public class BuildInfoTests
{
    [Fact]
    public void A_stamped_build_splits_into_version_and_commit()
    {
        var b = BuildInfo.Parse("0.1.0-alpha+5B5BD54F7F9F20453433991CB27B3C3F5312BBC8", "2026-10-31T14:00:00Z");

        Assert.Equal("0.1.0-alpha", b.Version);
        Assert.Equal("5b5bd54f7f9f20453433991cb27b3c3f5312bbc8", b.Commit);
        Assert.Equal("5b5bd54", b.CommitShort);
        Assert.Equal("0.1.0-alpha+5b5bd54", b.Display);
        Assert.Equal(new DateTimeOffset(2026, 10, 31, 14, 0, 0, TimeSpan.Zero), b.BuiltAt);
    }

    [Fact]
    public void An_unstamped_build_reports_its_version_without_inventing_a_commit()
    {
        var b = BuildInfo.Parse("0.1.0-alpha", null);

        Assert.Null(b.Commit);
        Assert.Null(b.CommitShort);
        Assert.Null(b.BuiltAt);
        Assert.Equal("0.1.0-alpha", b.Display);
    }

    [Theory]
    [InlineData("1.2.3+build.42")]     // build metadata that is not a sha
    [InlineData("1.2.3+abc")]          // hex, but too short to be a commit
    [InlineData("1.2.3+")]             // empty metadata
    public void Build_metadata_that_is_not_a_commit_is_not_reported_as_one(string informational)
    {
        var b = BuildInfo.Parse(informational, null);

        Assert.Equal("1.2.3", b.Version);
        Assert.Null(b.Commit);
        Assert.Equal("1.2.3", b.Display);
    }

    [Theory]
    [InlineData("not a date")]
    [InlineData("")]
    public void An_unreadable_build_timestamp_is_unknown_not_now(string builtAt) =>
        Assert.Null(BuildInfo.Parse("1.0.0", builtAt).BuiltAt);

    [Fact]
    public void A_timestamp_with_an_offset_is_normalised_to_utc()
    {
        var b = BuildInfo.Parse("1.0.0", "2026-10-31T09:00:00-05:00");

        Assert.Equal(new DateTimeOffset(2026, 10, 31, 14, 0, 0, TimeSpan.Zero), b.BuiltAt);
        Assert.Equal(TimeSpan.Zero, b.BuiltAt!.Value.Offset);
    }

    [Fact]
    public void The_running_build_is_read_from_the_application_assembly()
    {
        var current = BuildInfo.Current;

        Assert.False(string.IsNullOrWhiteSpace(current.Version));
        // Display is always the version, plus the short commit when one was stamped.
        Assert.Equal(current.CommitShort is { } c ? $"{current.Version}+{c}" : current.Version, current.Display);
    }
}
