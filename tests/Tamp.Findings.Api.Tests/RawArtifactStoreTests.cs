using System.Text;
using Tamp.Findings.Api.Ingest.Raw;
using Xunit;

namespace Tamp.Findings.Api.Tests;

// Raw evidence is stored gzip-compressed; the download path must return the exact original bytes, and
// XML must actually shrink (the reason we compress rather than store bytea raw).
public class RawArtifactStoreTests
{
    [Fact]
    public void Gzip_then_gunzip_round_trips_exactly()
    {
        var original = Encoding.UTF8.GetBytes("<TestRun><Results>" + string.Concat(Enumerable.Repeat("<r/>", 500)) + "</Results></TestRun>");
        var restored = RawArtifactStore.Gunzip(RawArtifactStore.Gzip(original));
        Assert.Equal(original, restored);
    }

    [Fact]
    public void Gzip_compresses_repetitive_xml()
    {
        var original = Encoding.UTF8.GetBytes(string.Concat(Enumerable.Repeat("<UnitTestResult outcome=\"Passed\"/>", 1000)));
        var compressed = RawArtifactStore.Gzip(original);
        Assert.True(compressed.Length < original.Length / 5, $"expected >5x compression, got {original.Length}→{compressed.Length}");
    }
}
