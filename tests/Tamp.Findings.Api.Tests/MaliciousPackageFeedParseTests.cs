using System.Text.Json;
using Tamp.Findings.Api.Services;

namespace Tamp.Findings.Api.Tests;

// TFND-211: turning an OSV MAL-* advisory into unauthorized-component entries.
public class MaliciousPackageFeedParseTests
{
    private static List<MaliciousPackageFeedSyncService.MalEntry> Parse(string json, string eco)
    {
        using var doc = JsonDocument.Parse(json);
        return MaliciousPackageFeedSyncService.Parse(doc.RootElement, eco).ToList();
    }

    [Fact]
    public void A_mal_advisory_yields_a_lowercased_versionless_entry_with_its_versions()
    {
        var e = Parse("""
            {"id":"MAL-2024-11505","summary":"Malicious code in Bunifu.Form (NuGet)",
             "affected":[{"package":{"name":"Bunifu.Form","ecosystem":"NuGet","purl":"pkg:nuget/Bunifu.Form"},
                          "versions":["1.0.0","8.3.53"]}]}
            """, "NuGet").Single();

        Assert.Equal("pkg:nuget/bunifu.form", e.Purl);
        Assert.Equal(["1.0.0", "8.3.53"], e.Versions);
        Assert.Equal("MAL-2024-11505", e.Id);
    }

    [Fact]
    public void A_missing_purl_is_built_from_the_package_name_and_a_missing_version_list_means_all_versions()
    {
        var e = Parse("""
            {"id":"MAL-1","affected":[{"package":{"name":"Evil-Pkg","ecosystem":"npm"}}]}
            """, "npm").Single();

        Assert.Equal("pkg:npm/evil-pkg", e.Purl);
        Assert.Empty(e.Versions);
    }

    [Fact]
    public void Non_mal_advisories_and_other_ecosystems_are_ignored()
    {
        Assert.Empty(Parse("""{"id":"GHSA-xxxx","affected":[{"package":{"name":"x","ecosystem":"npm"}}]}""", "npm"));
        Assert.Empty(Parse("""{"id":"MAL-2","affected":[{"package":{"name":"x","ecosystem":"PyPI"}}]}""", "npm"));
    }
}
