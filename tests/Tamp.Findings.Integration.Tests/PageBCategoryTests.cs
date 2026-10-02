using System.Net;

namespace Tamp.Findings.Integration.Tests;

[Collection(DatabaseCollection.Name)]
public sealed class PageBCategoryTests(DatabaseFixture fx)
{
    private readonly DatabaseFixture _fx = fx;

    public static readonly string[] Keys =
    [
        "cve", "secrets", "sastSevere", "sastLow", "dastSevere", "dastLow", "iacSevere",
        "coverage", "tests", "sbomStaleness", "license", "missingScanners", "quality",
    ];

    [SkippableFact]
    public async Task Every_category_key_renders_for_the_populated_build()
    {
        Skip.IfNot(_fx.Available, "TAMP_FINDINGS_TEST_DB not set");
        var w = await PageBWorld.GetAsync(_fx);
        foreach (var sha in new[] { w.ShaNew, w.ShaMid, w.ShaOld, "latest" })
        foreach (var key in Keys)
        {
            var (status, body) = await w.GetAsync(w.Build(sha, "score/" + key));
            Assert.True(status == HttpStatusCode.OK, $"{key}@{sha}: {status}");
            Assert.True(body.Contains($">{key}<") || body.Contains("No scored category"), $"{key}@{sha} rendered neither hero nor not-found");
        }
    }
}
