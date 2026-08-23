namespace Tamp.Findings.Api.Tests;

// Scan receipts (TFND-82). The card that makes "clean" and "never scanned"
// visibly different — problem 5 on the brief's list, and the distinction whose
// absence is precisely how a compliance attestation becomes false.
public class ScanReceiptTests : IClassFixture<TestApiFactory>
{
    private readonly TestApiFactory _factory;

    public ScanReceiptTests(TestApiFactory factory) => _factory = factory;

    [Fact]
    public async Task Receipts_are_not_rendered_when_the_posture_could_not_be_loaded()
    {
        // Without a database the hub renders Unavailable. Showing a receipts
        // grid there would be the exact failure mode the card exists to
        // prevent: a set of "never ran" cards implying we looked and found
        // nothing, when in fact we could not look at all.
        var client = _factory.CreateSignedIn();

        var body = await client.GetStringAsync("/c/BrewingCoder/p/tamp/build/179fe8b");

        Assert.Contains("Unavailable", body, StringComparison.Ordinal);
        Assert.DoesNotContain("Scan receipts", body, StringComparison.Ordinal);
        Assert.DoesNotContain("receipt--never", body, StringComparison.Ordinal);
    }
}
