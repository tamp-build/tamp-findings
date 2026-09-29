using Tamp.Findings.Api.Endpoints;
using Xunit;

namespace Tamp.Findings.Api.Tests;

// Commit identity for build reconciliation: an abbreviated sha and its full form name the same commit,
// so evidence posted under either lands on one build (the phantom-build-splitting fix).
public class BuildResolverShaTests
{
    [Theory]
    [InlineData("6648825", "6648825947dbe6bc1dbbbed01f7ef2f37804a9e9")]   // short is a prefix of full
    [InlineData("6648825947dbe6bc1dbbbed01f7ef2f37804a9e9", "6648825")]   // order doesn't matter
    [InlineData("6648825", "6648825")]                                     // identical
    [InlineData("6648825", "6648825947DBE6BC1")]                           // case-insensitive
    public void Same_commit_matches(string a, string b) =>
        Assert.True(BuildResolver.ShaIdentifiesSameCommit(a, b));

    [Theory]
    [InlineData("6648825", "abc1234def")]                                  // different commit
    [InlineData("664882", "6648825947dbe6bc1")]                            // 6 chars — below the abbreviation floor
    [InlineData("6648825", "6648826947dbe6bc1")]                           // diverges within the prefix
    public void Different_or_too_short_does_not_match(string a, string b) =>
        Assert.False(BuildResolver.ShaIdentifiesSameCommit(a, b));
}
